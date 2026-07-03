import datetime

from django.contrib.auth import get_user_model
from django.db import models
from django.conf import settings
from django.utils import timezone
from ajax_helpers.utils import random_string
from django.db.models import Q

from modal_2fa.utils import get_client_ip_address, get_custom_auth


class RememberDeviceCookie(models.Model):

    user = models.ForeignKey(getattr(settings, 'AUTH_USER_MODEL', 'auth.User'), on_delete=models.CASCADE)
    key = models.CharField(max_length=40, default=random_string)
    name = models.CharField(max_length=40, null=True, blank=True)
    last_used = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)
    user_agent = models.CharField(max_length=240, null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP')
    active = models.BooleanField(default=False)

    @staticmethod
    def cookie_name(user):
        return 'device_' + user.username.replace('@', '_')

    @staticmethod
    def cookie_key(request, user):
        return request.COOKIES.get(RememberDeviceCookie.cookie_name(user))

    @staticmethod
    def delete_cookie_key(response, user):
        response.delete_cookie(RememberDeviceCookie.cookie_name(user))

    @staticmethod
    def cookie_object(request, user, **kwargs):
        key = RememberDeviceCookie.cookie_key(request, user)
        if key:
            if ':' not in key:
                return RememberDeviceCookie.objects.filter(key=key, user=user, **kwargs).first()
            else:
                return RememberDeviceCookie.objects.filter(id=key.split(':')[1], user=user, **kwargs).first()

    @classmethod
    def test_cookie(cls, request, user, **kwargs):
        stored = cls.cookie_object(request, user, **kwargs)
        if stored and stored.key == RememberDeviceCookie.cookie_key(request, user).split(':')[0]:
            return True
        return False

    def set_cookie(self, response):
        # This is a 2FA-bypass token: keep it out of JS (httponly) and off
        # cross-site requests (samesite) in addition to https-only (secure).
        response.set_cookie(RememberDeviceCookie.cookie_name(self.user), value=f'{self.key}:{self.id}', secure=True,
                            httponly=True, samesite='Lax',
                            expires=timezone.now() + datetime.timedelta(days=365))

    @staticmethod
    def update_cookie(user, request, response):
        remember_cookie = RememberDeviceCookie.cookie_object(request, user)
        if remember_cookie:
            remember_cookie.key = random_string()
            remember_cookie.save()
            remember_cookie.set_cookie(response)


class WebauthnCredential(models.Model):
    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='webauthn')
    rp_id = models.CharField(max_length=80)
    credential_public_key = models.CharField(max_length=9000, blank=True, null=True)
    credential_id = models.CharField(max_length=9000, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True)
    last_used_on = models.DateTimeField(null=True)
    sign_count = models.IntegerField()

    def __str__(self):
        return f'{self.rp_id} {self.credential_id[:8]}'


class FailedLoginAttempt(models.Model):

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE, related_name='failed_login', null=True,
                             blank=True)
    ip_address = models.CharField(max_length=45, null=True, blank=True)
    failed_attempts = models.IntegerField()
    locked_time = models.DateTimeField(null=True, blank=True)

    @classmethod
    def check_request(cls, request, user, use_ip=True):
        # use_ip=False scopes the check to the user alone (no shared-IP clause).
        # The 2FA step uses this: the user is already known and each user's secret
        # is independent, so one attacker on a shared NAT must not block everyone.
        now = timezone.now()
        ip_address = get_client_ip_address(request)
        # An allowlisted IP (trusted office/VPN/NAT egress) is never blocked by the
        # shared-IP lockout; drop the IP clause and fall back to the user only.
        if use_ip and get_custom_auth().is_ip_excluded(ip_address):
            use_ip = False
        if use_ip and user:
            results = cls.objects.filter(Q(ip_address=ip_address) | Q(user=user))
        elif use_ip:
            results = cls.objects.filter(Q(ip_address=ip_address))
        elif user:
            results = cls.objects.filter(user=user)
        else:
            return True
        for r in results:
            if not r.locked_time:
                continue
            if r.locked_time > now:
                # Lockout window is still in effect.
                if r.user_id:
                    return 'Account locked'
                return f'IP Blocked {ip_address}'
            # The window has elapsed: clear the lock so the next window starts fresh.
            r.failed_attempts = 0
            r.locked_time = None
            r.save()
        return True

    @classmethod
    def clear_failed_attempts(cls, request, user, use_ip=True):
        if use_ip:
            cls.objects.filter(Q(ip_address=get_client_ip_address(request)) | Q(user=user)).delete()
        elif user:
            # User-scoped clear: leave the shared-IP counter alone (it may be
            # tracking other clients behind the same NAT).
            cls.objects.filter(user=user).delete()

    @classmethod
    def add_failed_attempt(cls, request, user, use_ip=True):
        lockout_time = (timezone.now() +
                        datetime.timedelta(seconds=getattr(settings, 'AUTHENTICATION_LOCKOUT_SECONDS', 30)))
        if use_ip:
            ip_address = get_client_ip_address(request)
            # Don't count or lock an allowlisted IP -- the per-user block below
            # still records the attempt, so individual accounts stay protected.
            if not get_custom_auth().is_ip_excluded(ip_address):
                ip_fail = cls.objects.filter(ip_address=ip_address, user__isnull=True).first()
                if ip_fail:
                    ip_fail.failed_attempts += 1
                    if ip_fail.failed_attempts > getattr(settings, 'AUTHENTICATION_IP_FAILED_ATTEMPTS', 20):
                        ip_fail.locked_time = lockout_time
                    ip_fail.save()
                else:
                    cls(ip_address=ip_address, failed_attempts=1).save()
        if user:
            user_fail = cls.objects.filter(user=user).first()
            if user_fail:
                user_fail.failed_attempts += 1
                if user_fail.failed_attempts > getattr(settings, 'AUTHENTICATION_USER_FAILED_ATTEMPTS', 10):
                    user_fail.locked_time = lockout_time
                user_fail.save()
            else:
                cls(user=user, failed_attempts=1).save()
