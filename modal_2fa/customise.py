from django.contrib.auth.views import PasswordResetView

from .urls import make_url_patterns, pattern_dict
from .auth import Modal2FA
from .models import RememberDeviceCookie
from .microsoft import MicrosoftCustomiseMixin, register_microsoft_urls


class CustomiseAuth(MicrosoftCustomiseMixin):
    """Per-project configuration hook for modal_2fa.

    Consumers subclass this and point ``settings.AUTHENTICATION_CUSTOMISATION``
    at the dotted path of their subclass. Override only the hooks you need;
    every method below has a working default.

    Override surface (note the decorator each one expects — keep it the same
    when overriding, or the call site will pass the wrong arguments):

    Policy hooks (called on the *class*, no instance/view bound):
      - ``user_2fa_optional(user) -> bool``       @staticmethod  — is 2FA optional for this user (default True)
      - ``password_login_allowed(user) -> bool``  @staticmethod  — may this user log in with a password (default True)
      - ``allowed_remember(user) -> bool``        @staticmethod  — show the "remember this device" option
      - ``max_cookies(user) -> int``            @staticmethod  — max trusted devices per user (default 2)
      - ``is_ip_excluded(ip) -> bool``          @classmethod   — exempt an IP/CIDR from the shared-IP lockout
      - ``excluded_ips: list[str]``             class attr     — IPs/CIDRs feeding the default is_ip_excluded

    View hook (called per request with the bound view instance):
      - ``customise_view(view) -> None``        @staticmethod  — mutate the view (size, css, templates, title)

    URL hook:
      - ``override_views() -> dict``            @staticmethod  — replace any name->(route, view) in pattern_dict

    Email template attributes (read by the relevant auth views):
      - ``invite_email_template`` / ``invite_txt_email_template`` / ``invite_subject_template``
      - ``reset_password_email_template`` / ``reset_password_txt_email_template`` / ``reset_password_subject_template``
    """

    invite_email_template = 'modal_2fa/emails/invite.html'
    invite_txt_email_template = 'modal_2fa/emails/invite_txt.html'
    invite_subject_template = 'modal_2fa/emails/invite_subject.txt'

    reset_password_email_template = None
    reset_password_txt_email_template = 'modal_2fa/emails/password_reset_email.html'
    reset_password_subject_template = 'modal_2fa/emails/password_reset_subject.txt'

    @staticmethod
    def override_views():
        """Return a dict of ``name -> (route, view)`` to merge over pattern_dict.

        Use this to swap any built-in auth view for a project-specific one
        without re-declaring the whole URL table.
        """
        return {}

    @classmethod
    def paths(cls, include_admin=False):
        # Copy so we don't mutate the shared module-level pattern_dict in place
        # (calling paths() more than once would otherwise keep appending to it).
        patterns = dict(pattern_dict)
        if include_admin:
            from modal_2fa.user_admin import UserAdminModal
            from modal_2fa.security_admin import SecurityAdminModal, ClearLockoutModal, ForceLogoutModal
            patterns['user_admin_modal'] = ('user-admin-modal/', UserAdminModal)
            patterns['security_admin_modal'] = ('security-admin-modal/', SecurityAdminModal)
            patterns['clear_lockout'] = ('clear-lockout/<slug:slug>/', ClearLockoutModal)
            patterns['force_logout'] = ('force-logout/<slug:slug>/', ForceLogoutModal)
        register_microsoft_urls(patterns)
        patterns.update(cls.override_views())
        return make_url_patterns(patterns)

    @staticmethod
    def customise_view(view):
        """Mutate the bound auth ``view`` in place (called on every auth view).

        Typical use: set modal ``size``, ``helper_class``, ``modal_title``, or a
        custom ``no_parent_template``. Returns nothing.
        """
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
        """Whether 2FA is optional for ``user`` (default True).

        Return False to force a user without a TOTP/WebAuthn device through 2FA
        setup rather than letting them log in with a password alone.
        """
        return True

    @staticmethod
    def allowed_remember(user):
        """Whether the "remember this device" option is offered to ``user``."""
        return True

    @staticmethod
    def manage_max_cookies(user, max_number):
        cookies = RememberDeviceCookie.objects.filter(user=user).order_by('last_used')
        if len(cookies) >= max_number:
            cookies[0].delete()

    @staticmethod
    def max_cookies(_user):
        """Maximum number of trusted "remember device" cookies per user (default 2)."""
        return 2

    @classmethod
    def max_cookies_already(cls, user):
        if RememberDeviceCookie.objects.filter(user=user).count() >= cls.max_cookies(user):
            return True
