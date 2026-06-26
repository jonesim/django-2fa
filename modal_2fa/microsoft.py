"""Optional Microsoft / Entra sign-in.

Everything specific to "Sign in with Microsoft" lives here so the feature can
evolve without touching the core auth modules. It is opt-in (like WebAuthn): the
button and OAuth routes are only wired up when the ``MS_*`` settings are present
(see :func:`microsoft_configured`) and ``msal`` is imported lazily.

Settings consumed:

* ``MS_CLIENT_ID``     Application (client) ID from the Azure App Registration.
* ``MS_TENANT_ID``     Directory (tenant) ID. Using the tenant ID (not ``common``)
  restricts sign-in to a single organisation.
* ``MS_CLIENT_SECRET`` A client secret *value* from Certificates & secrets.
* ``MS_REDIRECT_URI``  (optional) Absolute redirect URI registered in Azure. When
  omitted, the ``auth:ms_redirect`` route is reversed against the incoming
  request to build it.
* ``MS_SCOPES``        (optional) OAuth scopes; defaults to ``[]`` (sign-in only).
"""
import time

from django.conf import settings
from django.contrib.auth import get_user_model, login as auth_login
from django.contrib.auth.backends import ModelBackend
from django.db.models import ObjectDoesNotExist
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.http import urlencode
from django.views import View

from .backends import CookieBackend
from .utils import get_custom_auth, safe_redirect_url

UserModel = get_user_model()


# --- configuration helpers --------------------------------------------------

def microsoft_configured():
    return all(getattr(settings, name, None) for name in ('MS_CLIENT_ID', 'MS_TENANT_ID', 'MS_CLIENT_SECRET'))


def microsoft_authority():
    return f'https://login.microsoftonline.com/{settings.MS_TENANT_ID}'


# --- customisation hooks (mixed into CustomiseAuth) -------------------------

class MicrosoftCustomiseMixin:
    """Microsoft/Entra customisation hooks, mixed into ``CustomiseAuth``.

    Consumers override these on their own ``CustomiseAuth`` subclass exactly as
    before; they live here only to keep the Microsoft surface in one module.
    """

    #: How recent the Microsoft authentication must be (seconds) for it to count
    #: as the second factor. Guards against a stale SSO session being treated as
    #: a fresh multi-factor login.
    microsoft_fresh_seconds = 600

    #: Whether B2B *guest* accounts of the configured tenant may sign in. The
    #: single-tenant ``tid`` gate accepts both members and guests, so this is the
    #: switch that decides whether guests are turned away. Defaults to members-only;
    #: set ``True`` to admit guests as well.
    microsoft_allow_guests = False

    @staticmethod
    def microsoft_is_guest(claims):
        """Whether the verified claims belong to a B2B *guest* of the tenant.

        Detected without depending on any single optional claim, so it works
        whether or not ``acct`` is configured in Entra:

        * ``acct`` — when present, ``1`` means guest and ``0`` means member. If it
          is present it is authoritative.
        * ``idp`` vs ``iss`` — Entra issues the token *as your tenant*, so ``iss``
          (and ``tid``) point at your tenant even for a guest; they agreeing tells
          you nothing. The ``idp`` claim records where the user actually
          authenticated and is only emitted when it differs from ``iss`` — i.e.
          for guests/external identities. A present ``idp`` that differs from
          ``iss`` therefore reliably marks a guest, with no optional claim needed.

        Override to apply a different rule (e.g. allow-listing specific home idps).
        """
        if claims.get('acct') == 1:
            return True
        if claims.get('acct') == 0:
            return False
        idp = claims.get('idp')
        return bool(idp and idp != claims.get('iss'))

    @classmethod
    def microsoft_allowed(cls, claims):
        """Whether a Microsoft sign-in is permitted, beyond the single-tenant gate.

        The ``tid`` gate in :class:`MsCallbackView` accepts both home members and
        B2B guests of the tenant. By default this restricts sign-in to members;
        set :attr:`microsoft_allow_guests` to ``True`` to admit guests too. Guest
        detection lives in :meth:`microsoft_is_guest`. Override this method for a
        fully custom policy.
        """
        return cls.microsoft_allow_guests or not cls.microsoft_is_guest(claims)

    @staticmethod
    def microsoft_user(claims):
        """Map verified Microsoft ID-token claims to an existing Django user.

        Match-existing-only: returns ``None`` (sign-in fails) when no user matches.
        Override to provision users or match on a different field.
        """
        username = claims.get('preferred_username') or claims.get('email')
        if not username:
            return None
        try:
            # noinspection PyProtectedMember
            return UserModel._default_manager.get_by_natural_key(username)
        except ObjectDoesNotExist:
            return None

    @classmethod
    def microsoft_satisfies_2fa(cls, claims):
        """Whether a Microsoft sign-in counts as the second factor.

        Defaults to ``True`` only when the ID token proves multi-factor auth
        happened recently: an MFA-class method in ``amr`` and a fresh ``auth_time``.
        Otherwise the user still completes the normal TOTP/WebAuthn 2FA step.
        """
        amr = claims.get('amr') or []
        mfa_methods = {'mfa', 'otp', 'fido', 'hwk', 'phr', 'phh'}
        if not mfa_methods.intersection(amr):
            return False
        auth_time = claims.get('auth_time')
        if not auth_time:
            return False
        return (time.time() - int(auth_time)) <= cls.microsoft_fresh_seconds


# --- login button -----------------------------------------------------------

def microsoft_login_button():
    """HTML for the 'Sign in with Microsoft' button (brand logo + label).

    Returned as a plain string so callers can wrap it in whatever they need
    (e.g. a crispy ``HTML`` layout object) without this module depending on the
    form layer.
    """
    # Microsoft's four-square brand mark, inlined as SVG so the library carries
    # no static-asset dependency on the consuming project.
    logo = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" '
        'viewBox="0 0 21 21" class="mr-2" aria-hidden="true">'
        '<rect x="1" y="1" width="9" height="9" fill="#f25022"/>'
        '<rect x="11" y="1" width="9" height="9" fill="#7fba00"/>'
        '<rect x="1" y="11" width="9" height="9" fill="#00a4ef"/>'
        '<rect x="11" y="11" width="9" height="9" fill="#ffb900"/>'
        '</svg>'
    )
    return (
        f'<div class="text-center mt-2">'
        f'<a href="{reverse("auth:ms_login")}" '
        f'class="btn btn-outline-secondary d-inline-flex align-items-center">'
        f'{logo}Sign in with Microsoft</a></div>'
    )


# --- backend ----------------------------------------------------------------

class MicrosoftBackend(ModelBackend):
    """Authenticate a user from verified Microsoft/Entra ID-token claims.

    Match-existing-only: the claims are mapped to an existing Django user via the
    customisation hook ``microsoft_user`` (which defaults to a natural-key lookup
    on ``preferred_username``). No user is ever created here.
    """

    def __init__(self):
        super().__init__()
        self.customisation_class = get_custom_auth()

    def authenticate(self, request, ms_claims=None, **kwargs):
        if ms_claims is None:
            return None
        return self.customisation_class.microsoft_user(ms_claims)


# --- MSAL views -------------------------------------------------------------

class MsAuthMixin:
    """Shared MSAL helpers for the optional Microsoft sign-in views."""

    @staticmethod
    def msal_app():
        import msal
        return msal.ConfidentialClientApplication(
            settings.MS_CLIENT_ID,
            authority=microsoft_authority(),
            client_credential=settings.MS_CLIENT_SECRET,
        )

    @staticmethod
    def redirect_uri(request):
        explicit = getattr(settings, 'MS_REDIRECT_URI', None)
        if explicit:
            return explicit
        uri = request.build_absolute_uri(reverse('auth:ms_redirect'))
        # Behind a TLS-terminating proxy (e.g. Docker/Traefik/Cloudflare) the
        # container is reached over plain HTTP, so request.scheme is 'http' and
        # build_absolute_uri yields an http:// redirect URI. Azure rejects that:
        # every non-localhost redirect URI it accepts must be https. Force the
        # scheme up to https for non-local hosts so the generated URI matches the
        # one registered in Azure without relying on the proxy forwarding
        # X-Forwarded-Proto. (Set MS_REDIRECT_URI explicitly to override entirely.)
        if uri.startswith('http://') and request.get_host().split(':')[0] not in ('localhost', '127.0.0.1'):
            uri = 'https://' + uri[len('http://'):]
        return uri


class MsLoginView(MsAuthMixin, View):
    """Start an interactive Microsoft auth-code flow and redirect to Microsoft."""

    def get(self, request, *args, **kwargs):
        flow = self.msal_app().initiate_auth_code_flow(
            getattr(settings, 'MS_SCOPES', []),
            redirect_uri=self.redirect_uri(request),
            # Interactive (not prompt='none'): we want a *fresh* authentication so
            # the returned token's amr/auth_time genuinely reflect this sign-in.
            prompt='select_account',
        )
        request.session['ms_auth_flow'] = flow
        if 'next' in request.GET:
            request.session['ms_next'] = request.GET['next']
        return HttpResponseRedirect(flow['auth_uri'])


class MsCallbackView(MsAuthMixin, View):
    """Handle the Microsoft redirect: validate claims and log the user in."""

    def get(self, request, *args, **kwargs):
        login_url = reverse('auth:login')
        flow = request.session.pop('ms_auth_flow', None)
        # Validate the stored next at the redirect decision point, so even a
        # tampered session value can't drive an open redirect.
        next_url = safe_redirect_url(request, request.session.pop('ms_next', None))
        if not flow:
            return HttpResponseRedirect(login_url)
        try:
            result = self.msal_app().acquire_token_by_auth_code_flow(flow, dict(request.GET.items()))
        except ValueError:
            return HttpResponseRedirect(login_url)
        if 'error' in result:
            # login_required / interaction_required / access_denied etc.
            return HttpResponseRedirect(login_url)

        claims = result.get('id_token_claims', {})
        # Single-tenant gate: the token must come from the configured tenant. Note
        # ``tid`` is the *resource* tenant the token was issued from, so B2B guests
        # of that tenant pass this check too; ``microsoft_allowed`` applies any
        # further policy (members-only by default).
        if claims.get('tid') != settings.MS_TENANT_ID:
            return HttpResponseRedirect(login_url)
        if not get_custom_auth().microsoft_allowed(claims):
            return HttpResponseRedirect(login_url)

        user = MicrosoftBackend().authenticate(request, ms_claims=claims)
        if user is None:
            # Match-existing-only: no Django user for this Microsoft account.
            return HttpResponseRedirect(login_url)

        # Log in via the registered CookieBackend path so the session persists
        # (as Modal2FA does); the authentication_method marker records that this
        # was a Microsoft sign-in.
        if get_custom_auth().microsoft_satisfies_2fa(claims):
            auth_login(request, user, backend='modal_2fa.auth.CookieBackend')
            request.session['authentication_method'] = 'microsoft'
            # Keep the verified ID-token claims so consumers can inspect them later
            # (cleared automatically on logout when the session is flushed).
            request.session['ms_claims'] = claims
            return HttpResponseRedirect(next_url or settings.LOGIN_REDIRECT_URL)

        # MFA not proven by the token: fall through to the normal 2FA step.
        CookieBackend.set_part_login(request, user.username)
        url = reverse('auth:auth_2fa')
        if next_url:
            url += '?' + urlencode({'next': next_url})
        return HttpResponseRedirect(url)


# --- url registration -------------------------------------------------------

def register_microsoft_urls(pattern_dict):
    """Add the optional Microsoft sign-in routes when the MS_* settings are set."""
    if microsoft_configured():
        pattern_dict['ms_login'] = ('microsoft/login/', MsLoginView)
        pattern_dict['ms_redirect'] = ('microsoft/redirect/', MsCallbackView)
