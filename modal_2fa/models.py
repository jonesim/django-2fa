import datetime
from django.db import models
from django.conf import settings
from ajax_helpers.utils import random_string


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
        return 'device_' + user.username

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
            return RememberDeviceCookie.objects.filter(key=key, user=user, **kwargs).first()

    def set_cookie(self, response):
        response.set_cookie(RememberDeviceCookie.cookie_name(self.user), value=self.key, secure=True,
                            expires=datetime.datetime.today() + datetime.timedelta(days=365))

    @staticmethod
    def update_cookie(user, request, response):
        remember_cookie = RememberDeviceCookie.cookie_object(request, user)
        if remember_cookie:
            remember_cookie.key = random_string()
            remember_cookie.save()
            remember_cookie.set_cookie(response)
