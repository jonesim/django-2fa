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
            if not self.customisation_class.password_login_allowed(user):
                # Entra-only user: refuse the password path entirely. The Microsoft
                # backend authenticates from verified claims (no password), so SSO
                # sign-in for this same user is unaffected.
                return None
            if not self.customisation_class.two_factor_enabled(request):
                # 2FA is out of scope for this request (a different host, schema or
                # site to the one it protects): behave as a plain ModelBackend and
                # hand the user straight back. Checked before the trusted-device
                # lookup so a request from outside the 2FA area never reads
                # modal_2fa's tables, and never parks a part_login the auth views
                # in that area would not be there to consume.
                return user
            if RememberDeviceCookie.test_cookie(request, user, active=True):
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
