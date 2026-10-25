from modal_2fa.customise import CustomiseAuth
from django.utils.safestring import mark_safe
from django_modals.form_helpers import SmallHelper


class ExampleCustomise(CustomiseAuth):

    @staticmethod
    def customise_view(view):
        view.center_header = True
        view.size = 'md'
        view.helper_class = SmallHelper
        if hasattr(view, 'modal_title'):
            image = '<img src="/static/HTML5.svg" width="28">'
            view.modal_title = mark_safe(
                f'<span class="m-auto">{image}<span class="ml-2">{view.modal_title}</span></span>'
            )
        view.no_parent_template = 'blank_page_img.html'

    @staticmethod
    def allowed_remember(user):
        if user.username == 'ian5':
            return False
        return True

    @staticmethod
    def user_2fa_optional(user):
        # 2FA is optional in the demo unless the user is in the 'require-2fa'
        # group. NOTE: don't hard-return False here -- the test suite runs
        # under this class and its plain-login tests then fail; put your dev
        # users in the group instead (user admin or `manage.py shell`).
        return not user.groups.filter(name='require-2fa').exists()

    @staticmethod
    def password_login_allowed(user):
        # Members of the 'sso-only' group are Entra-only: their password is
        # rejected and they must use "Sign in with Microsoft". Inert for everyone
        # else, so normal password login is unaffected.
        return not user.groups.filter(name='sso-only').exists()

    @staticmethod
    def microsoft_satisfies_2fa(claims):
        # The Entra ID token carries no amr/auth_time, so MFA can't be read from
        # it. We trust a successful single-tenant Microsoft sign-in as the second
        # factor on the assumption that the tenant enforces MFA via Conditional
        # Access. If that assumption ever fails, switch to an Entra authentication
        # context (acr/amr) and verify it here instead.
        return True
