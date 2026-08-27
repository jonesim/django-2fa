"""Optional Wagtail support: shadow Wagtail's own auth URLs and gate its admin.

Wagtail ships three unauthenticated entry points under its admin prefix --
``login/``, ``logout/`` and ``password_reset/`` -- everything else in
``wagtailadmin_urls`` is wrapped in ``require_admin_access``. Its login form runs
Django's ``AuthenticationForm``, so it reaches ``CookieBackend`` but bypasses the
``FailedLoginAttempt`` accounting, the Entra-only message and the 2FA step that
``ModalLoginView`` applies.

Django resolves an incoming path against the *first* matching pattern, so the
patterns built here shadow Wagtail's as long as the consumer's
``CustomiseAuth.paths()`` include sits above ``include(wagtailadmin_urls)``.

Everything in this module is inert until ``wagtail_admin_prefix`` is set on the
project's ``CustomiseAuth`` subclass -- Wagtail itself is never imported.
"""

from django.conf import settings
from django.contrib.auth.views import LogoutView
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect
from django.urls import path, reverse
from django.utils.http import urlencode

from .utils import get_custom_auth, safe_redirect_url

# Paths under the admin prefix that must stay reachable without a second factor:
# the shadow login/logout/password-reset routes themselves.
EXEMPT_PREFIXES = ('login/', 'logout/', 'password_reset/')


# --- customisation hooks (mixed into CustomiseAuth) -------------------------

class WagtailCustomiseMixin:
    """Wagtail hooks, mixed into ``CustomiseAuth``.

    Set ``wagtail_admin_prefix`` to the prefix ``wagtailadmin_urls`` is mounted
    at (the same string passed to ``path()``) to enable both the URL shadowing
    and ``Wagtail2FAMiddleware``.
    """

    #: Prefix Wagtail's admin is mounted at, e.g. ``'admin/'`` or ``'cms/'``.
    #: ``None`` disables everything in this module.
    wagtail_admin_prefix = None

    #: ``session['authentication_method']`` values that count as verified for the
    #: Wagtail admin. ``'cookie'`` is excluded on purpose -- a trusted-device
    #: cookie skips the second factor, and ``AdminSite2FA`` holds the Django admin
    #: to the same standard. ``'microsoft'`` is accepted so Entra users, whose
    #: second factor happens at the IdP, are not locked out.
    wagtail_2fa_methods = ('2fa', 'microsoft')


# --- helpers ---------------------------------------------------------------

def wagtail_admin_root(prefix):
    """Normalise a URLConf prefix into a leading-and-trailing-slash path."""
    return '/' + prefix.strip('/') + '/'


def _redirect_view(url_name):
    """A view that unconditionally redirects to ``url_name``.

    Reversed per request rather than at URLConf import time, so this module can
    be imported while the auth patterns are still being built.
    """
    def view(_request, **_kwargs):
        return HttpResponseRedirect(reverse(url_name))
    return view


def wagtail_login_redirect(request):
    """Send Wagtail's login URL to the modal login, preserving ``next``."""
    prefix = get_custom_auth().wagtail_admin_prefix
    default = wagtail_admin_root(prefix) if prefix else settings.LOGIN_REDIRECT_URL
    next_url = safe_redirect_url(request, request.GET.get('next'), fallback=default)
    return HttpResponseRedirect(reverse('auth:login') + '?' + urlencode({'next': next_url}))


def wagtail_url_patterns(customise_cls):
    """Patterns that shadow Wagtail's auth URLs, or ``[]`` when not configured."""
    prefix = getattr(customise_cls, 'wagtail_admin_prefix', None)
    if prefix is None:
        return []
    prefix = prefix.strip('/')
    if not prefix:
        # A root-mounted prefix would shadow the whole site and make the
        # middleware gate every request -- fail loudly rather than silently.
        raise ImproperlyConfigured('wagtail_admin_prefix must name the prefix wagtailadmin_urls is mounted at, '
                                   "e.g. 'admin/'. Use None to disable Wagtail support.")
    prefix += '/'
    reset_redirect = _redirect_view('auth:reset_password')
    # Mirror pattern_dict['logout'] rather than redirecting: LogoutView is
    # POST-only and Wagtail's admin posts to it, so a 302 would downgrade the
    # request to GET and 405.
    logout_next = getattr(settings, 'LOGOUT_REDIRECT_URL', None) or settings.LOGIN_URL
    return [
        path(f'{prefix}login/', wagtail_login_redirect, name='wagtail_login'),
        path(f'{prefix}logout/', LogoutView.as_view(next_page=logout_next), name='wagtail_logout'),
        path(f'{prefix}password_reset/', reset_redirect, name='wagtail_password_reset'),
        path(f'{prefix}password_reset/done/', reset_redirect, name='wagtail_password_reset_done'),
        # Only reachable from emails Wagtail sent before this was wired up --
        # modal_2fa's own reset emails link to auth:password_reset_confirm.
        path(f'{prefix}password_reset/confirm/<uidb64>/<token>/', reset_redirect,
             name='wagtail_password_reset_confirm'),
        path(f'{prefix}password_reset/complete/', _redirect_view('auth:login'),
             name='wagtail_password_reset_complete'),
    ]


# --- middleware ------------------------------------------------------------

class Wagtail2FAMiddleware:
    """Require a second factor across the Wagtail admin.

    The equivalent of ``AdminSite2FA.has_permission`` for Wagtail, which has no
    comparable hook. Install after ``AuthenticationMiddleware``.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.check_request(request) or self.get_response(request)

    @staticmethod
    def check_request(request):
        customisation_class = get_custom_auth()
        prefix = getattr(customisation_class, 'wagtail_admin_prefix', None)
        if not prefix:
            return None
        root = wagtail_admin_root(prefix)
        # path_info excludes any script prefix, so it lines up with the URLConf.
        if not request.path_info.startswith(root):
            return None
        if any(request.path_info.startswith(root + exempt) for exempt in EXEMPT_PREFIXES):
            return None
        user = getattr(request, 'user', None)
        if user is None or not user.is_authenticated:
            # Anonymous users are Wagtail's own redirect to WAGTAILADMIN_LOGIN_URL.
            return None
        if request.session.get('authentication_method') in customisation_class.wagtail_2fa_methods:
            return None
        # Not auth_2fa_url(): that reads `next` from request.GET, which here is
        # the Wagtail page's own query string rather than where to return to.
        return HttpResponseRedirect(reverse('auth:auth_2fa') + '?' + urlencode({'next': request.get_full_path()}))
