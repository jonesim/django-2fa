import ipaddress

from django.contrib.auth import get_user_model
from django.contrib.auth.views import PasswordResetView

from .urls import make_url_patterns, pattern_dict
from .auth import Modal2FA
from .models import RememberDeviceCookie
from .microsoft import MicrosoftCustomiseMixin, register_microsoft_urls
from .wagtail_auth import WagtailCustomiseMixin, wagtail_url_patterns


class CustomiseAuth(MicrosoftCustomiseMixin, WagtailCustomiseMixin):
    """Per-project configuration hook for modal_2fa.

    Consumers subclass this and point ``settings.AUTHENTICATION_CUSTOMISATION``
    at the dotted path of their subclass. Override only the hooks you need;
    every method below has a working default.

    Override surface (note the decorator each one expects — keep it the same
    when overriding, or the call site will pass the wrong arguments):

    Policy hooks (called on the *class*, no instance/view bound):
      - ``user_2fa_optional(user) -> bool``       @staticmethod  — is 2FA optional for this user (default True)
      - ``two_factor_enabled(request) -> bool``  @staticmethod  — does 2FA apply to this request at all (default True)
      - ``password_login_allowed(user) -> bool``  @staticmethod  — may this user log in with a password (default True)
      - ``allow_passkeys(user) -> bool``          @staticmethod  — may this user register and sign in with passkeys
      - ``allow_totp(user) -> bool``              @staticmethod  — may this user enrol an authenticator app
      - ``passkey_user_verification(user) -> str`` / ``passkey_resident_key(user) -> str``  @staticmethod
        — WebAuthn requirements ('discouraged' / 'preferred' / 'required')
      - ``allowed_remember(user) -> bool``        @staticmethod  — show the "remember this device" option
      - ``max_cookies(user) -> int``            @staticmethod  — max trusted devices per user (default 2)
      - ``is_ip_excluded(ip) -> bool``          @classmethod   — exempt an IP/CIDR from the shared-IP lockout
      - ``excluded_ips: list[str]``             class attr     — IPs/CIDRs feeding the default is_ip_excluded
      - ``factor_management_methods: tuple[str]`` class attr   — authentication_method values allowed to manage
        second factors without a step-up (default ``('2fa', 'microsoft')``; 'cookie' is deliberately excluded)

    Access hooks — note these take ``(user, request=None)``, not ``user`` alone
    like the policy hooks above. ``request`` is supplied whenever the caller has
    one, for permission systems that depend on session or site state:
      - ``can_manage_users(user, request=None) -> bool``     @staticmethod  — user CRUD, user table, invites
      - ``can_manage_security(user, request=None) -> bool``  @staticmethod  — security admin (lockouts, sessions)

    View hook (called per request with the bound view instance):
      - ``customise_view(view) -> None``        @staticmethod  — mutate the view (size, css, templates, title)

    URL hook:
      - ``override_views() -> dict``            @staticmethod  — replace any name->(route, view) in pattern_dict

    Wagtail (all inert unless the prefix is set — see wagtail_auth.py):
      - ``wagtail_admin_prefix: str | None``    class attr     — prefix wagtailadmin_urls is mounted at, e.g. 'cms/'.
        Setting it makes paths() shadow Wagtail's own login/logout/password-reset URLs, and enables
        ``modal_2fa.wagtail_auth.Wagtail2FAMiddleware``. The include must sit *above* the Wagtail one.
      - ``wagtail_2fa_methods: tuple[str]``     class attr     — authentication_method values the middleware
        accepts for the Wagtail admin (default ``('2fa', 'microsoft')``)

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

    # IP allowlist for the brute-force lockout. Addresses / CIDR ranges here are
    # never blocked by the *shared-IP* lockout (e.g. trusted office / VPN / NAT
    # egress, where one bad actor would otherwise lock out everyone). The
    # per-user lockout still applies. Consumers can either set this list or
    # override is_ip_excluded() for dynamic logic.
    excluded_ips = []   # e.g. ['10.0.0.0/24', '203.0.113.5']

    # Sessions that may add, change or remove second factors (and trusted
    # devices) directly. Any other session of a user who has a factor -- a
    # trusted-device cookie login, or one from before the user enrolled -- is
    # sent through the 2FA modal first, so it can't enrol a factor of its own
    # and upgrade itself to '2fa'.
    factor_management_methods = ('2fa', 'microsoft')

    @classmethod
    def is_ip_excluded(cls, ip_address):
        if not ip_address:
            return False
        try:
            addr = ipaddress.ip_address(ip_address)
        except ValueError:
            return False
        for entry in cls.excluded_ips:
            try:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue   # ignore malformed allowlist entries rather than 500
        return False

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
        # The Wagtail shadow routes live at the project root, not under auth/,
        # so they are appended to the returned list rather than to pattern_dict.
        return make_url_patterns(patterns) + wagtail_url_patterns(cls)

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

        Return False to force a user without a second factor (passkey or TOTP)
        through 2FA setup rather than letting them log in with a password alone.

        NOTE: the demo project's ``ExampleCustomise`` overrides this hook --
        when testing with ``django_examples``, change it there, not here.
        """
        return True

    @staticmethod
    def allow_passkeys(user):
        """Whether ``user`` may register and use passkeys (default True).

        Return False to hide the passkey option from the 2FA setup screen and
        the "Add passkey" button from Passkeys & trusted devices, and to stop
        the user's existing passkeys counting as a second factor: they can't
        sign in with them, and are offered setup (authenticator app, if
        allowed) instead. The option is also disabled automatically when the
        ``webauthn`` package isn't installed.
        """
        return True

    @staticmethod
    def passkey_user_verification(user):
        """User-verification requirement for passkey registration and login:
        'discouraged' (default), 'preferred' or 'required'.

        Passkeys here are a *second* factor -- the password has already been
        entered -- so a touch proving possession is the point. 'discouraged'
        keeps hardware keys touch-only; anything stronger makes browsers demand
        the key's PIN (and Windows will force PIN setup on a PIN-less key).
        Platform authenticators (Windows Hello, Face ID) verify the user
        regardless. Raise it if passkeys must stand alone, e.g. for a future
        passwordless flow.
        """
        return 'discouraged'

    @staticmethod
    def passkey_resident_key(user):
        """Resident-key (discoverable credential) preference for new passkey
        registrations: 'discouraged' (default), 'preferred' or 'required'.

        'discouraged' keeps hardware security keys (YubiKeys etc.) registerable
        without a PIN -- Windows in particular escalates anything stronger into
        mandatory PIN setup on the key. Platform authenticators create synced
        discoverable passkeys regardless of this value. Raise it only if you
        plan a passwordless flow that must include hardware keys.
        """
        return 'discouraged'

    @staticmethod
    def allow_totp(user):
        """Whether ``user`` may enrol an authenticator app (default True).

        Return False to remove the authenticator-app option from the 2FA setup
        screen and the "Change / Set up authenticator app" menu entry, leaving
        passkeys as the only second factor on offer. An app the user already
        enrolled keeps working for sign-in.
        """
        return True

    @staticmethod
    def two_factor_enabled(request):
        """Whether the 2FA flow applies to this request at all (default True).

        ``user_2fa_optional`` answers "is 2FA optional *for this user*"; this answers
        "is this request even in the area 2FA protects". They are different questions
        for a project that mounts the auth views over part of a larger site — a
        control panel on one host, or one schema of a multi-tenant app — and
        authenticates users elsewhere through the same ``AUTHENTICATION_BACKENDS``.

        Returning False makes ``CookieBackend`` behave as a plain ``ModelBackend``
        for that request: no trusted-device lookup, no device lookup, and no
        part_login parked in the session for auth views that are not routed there to
        consume. Without it, such a project has to keep ``ModelBackend`` behind
        ``CookieBackend`` as a fall-through, which then has to be defended against on
        the side where 2FA *is* required.

        ``request`` may be None: ``authenticate()`` can be called without one, and
        there is then nothing to scope against, so the default answer applies.
        """
        return True

    @staticmethod
    def password_login_allowed(user):
        """Whether ``user`` may authenticate with a password (default True).

        Return False to make a user *Entra-only*: their password is rejected at
        the backend (``CookieBackend.authenticate``) and they must sign in with
        "Sign in with Microsoft". Note: only meaningful when Microsoft sign-in is
        configured -- otherwise a user for whom this returns False has no way in.
        """
        return True

    @staticmethod
    def can_manage_users(user, request=None):
        """Whether ``user`` may create/edit users, see the user table, and send invites.

        Default checks the ``change`` permission on the project's own user model
        (via ``get_user_model()``), so it stays correct under a swapped
        ``AUTH_USER_MODEL`` -- a hardcoded ``auth.change_user`` would name a model
        that no longer exists. ``request`` is supplied whenever the caller has one;
        override and use it for permission systems that depend on session or site
        state rather than the built-in ``user.groups`` M2M.
        """
        model = get_user_model()
        return user.has_perm(f'{model._meta.app_label}.change_{model._meta.model_name}')

    @staticmethod
    def can_manage_security(user, request=None):
        """Whether ``user`` may reach security admin (lockouts, active sessions).

        Default requires ``is_superuser``. Override for projects where superuser
        status comes from group or role membership instead of the flag.
        """
        return user.is_superuser

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
