from django.contrib.auth.views import PasswordResetView

from .urls import make_url_patterns, pattern_dict
from .auth import Modal2FA
from .models import RememberDeviceCookie


class CustomiseAuth:

    invite_email_template = 'modal_2fa/emails/invite.html'
    invite_txt_email_template = 'modal_2fa/emails/invite_txt.html'
    invite_subject_template = 'modal_2fa/emails/invite_subject.txt'

    reset_password_email_template = None
    reset_password_txt_email_template = 'registration/password_reset_email.html'
    reset_password_subject_template = 'registration/password_reset_subject.txt'

    @staticmethod
    def override_views():
        return {}

    @classmethod
    def paths(cls):
        patterns = pattern_dict
        patterns.update(cls.override_views())
        return make_url_patterns(patterns)

    @staticmethod
    def customise_view(view):
        return

    def set_attribute(self, attribute_name):
        if hasattr(self, attribute_name):
            setattr(self.view, attribute_name, getattr(self, attribute_name))

    def __init__(self, view):
        self.view = view
        if isinstance(view, PasswordResetView):
            self.set_attribute('email_template_name')
            self.set_attribute('subject_template_name')

        if isinstance(view, Modal2FA):
            self.set_attribute('allowed_remember')

    @staticmethod
    def user_2fa_optional(user):
        return True

    @staticmethod
    def allowed_remember(user):
        return True

    @staticmethod
    def manage_max_cookies(user, max_number):
        cookies = RememberDeviceCookie.objects.filter(user=user).order_by('last_used')
        if len(cookies) >= max_number:
            cookies[0].delete()

    @staticmethod
    def max_cookies(_user):
        return 2

    @classmethod
    def max_cookies_already(cls, user):
        if RememberDeviceCookie.objects.filter(user=user).count() >= cls.max_cookies(user):
            return True
