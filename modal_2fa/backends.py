from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from django_otp import user_has_device

from .models import RememberDeviceCookie
from .utils import get_custom_auth

UserModel = get_user_model()


class CookieBackend(ModelBackend):

    part_login_key = 'part_login'

    def __init__(self):
        super().__init__()
        self.customisation_class = get_custom_auth()

    @staticmethod
    def get_part_login(request):
        return request.session.get(CookieBackend.part_login_key)

    @staticmethod
    def set_part_login(request, username):
        request.session[CookieBackend.part_login_key] = username

    @staticmethod
    def delete_part_login(request):
        request.session.pop(CookieBackend.part_login_key, None)

    @staticmethod
    def get_part_login_user(request):
        # noinspection PyProtectedMember
        return UserModel._default_manager.get_by_natural_key(CookieBackend.get_part_login(request))

    def authenticate(self, request, username=None, password=None, device=None, token=None, **kwargs):
        if device is None:
            user = super().authenticate(request, username, password, **kwargs)
            if not user:
                return
            if RememberDeviceCookie.cookie_object(request, user, active=True):
                request.session['authentication_method'] = 'cookie'
                return user
            elif not user_has_device(user) and self.customisation_class.user_2fa_optional(user):
                return user
            elif user:
                self.set_part_login(request, user.username)
        else:
            if device.verify_token(token):
                request.session['authentication_method'] = '2fa'
                if request.user.is_authenticated:
                    user = request.user
                else:
                    user = self.get_part_login_user(request)
                self.delete_part_login(request)
                return user
