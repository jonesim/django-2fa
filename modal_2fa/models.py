import datetime

from django.contrib.auth import get_user_model
from django.db import models
from django.conf import settings
from ajax_helpers.utils import random_string
from django.db.models import Q

from modal_2fa.utils import get_client_ip_address


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
        response.set_cookie(RememberDeviceCookie.cookie_name(self.user), value=f'{self.key}:{self.id}', secure=True,
                            expires=datetime.datetime.today() + datetime.timedelta(days=365))

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
    ip_address = models.CharField(max_length=20, null=True, blank=True)
    failed_attempts = models.IntegerField()
    locked_time = models.DateTimeField(null=True, blank=True)

    @classmethod
    def check_request(cls, request, user):
        if user:
            results = cls.objects.filter(Q(ip_address=get_client_ip_address(request)) | Q(user=user))
        else:
            results = cls.objects.filter(Q(ip_address=get_client_ip_address(request)))
        for r in results:
            if r.locked_time and r.locked_time < datetime.datetime.now():
                return 'Time out until' + str(r.locked_time)
            if r.user_id:
                if r.failed_attempts > getattr(settings, 'AUTHENTICATION_USER_FAILED_ATTEMPTS', 10):
                    return 'Account locked'
            else:
                if r.failed_attempts > getattr(settings, 'AUTHENTICATION_IP_FAILED_ATTEMPTS', 20):
                    return f'IP Blocked {get_client_ip_address(request)}'
        return True

    @classmethod
    def clear_failed_attempts(cls, request, user):
        cls.objects.filter(Q(ip_address=get_client_ip_address(request)) | Q(user=user)).delete()

    @classmethod
    def add_failed_attempt(cls, request, user):
        ip_address = get_client_ip_address(request)
        ip_fail = cls.objects.filter(ip_address=ip_address).first()
        if ip_fail:
            ip_fail.failed_attempts += 1
            if ip_fail.failed_attempts > getattr(settings, 'AUTHENTICATION_IP_FAILED_LOCKOUT', 9999):
                ip_fail.locked_time = (datetime.datetime.now() +
                                       datetime.timedelta(seconds=settings.get('AUTHENTICATION_LOCKOUT_SECONDS', 30)))
            ip_fail.save()
        else:
            cls(ip_address=ip_address, failed_attempts=1).save()
        user_fail = cls.objects.filter(user=user).first()
        if user_fail:
            user_fail.failed_attempts += 1
            if user_fail.failed_attempts > getattr(settings, 'AUTHENTICATION_USER_FAILED_LOCKOUT', 9999):
                user_fail.locked_time = (datetime.datetime.now() +
                                         datetime.timedelta(seconds=getattr(settings,
                                                                            'AUTHENTICATION_LOCKOUT_SECONDS', 30)))
            user_fail.save()
        else:
            cls(user=user, failed_attempts=1).save()
