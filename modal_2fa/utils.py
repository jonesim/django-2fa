from django.conf import settings
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.module_loading import import_string


def safe_redirect_url(request, url, fallback=None):
    """Return ``url`` only if it is a safe local redirect target, else ``fallback``.

    Mirrors Django's ``LoginView`` guard: the URL must resolve to the current host
    (relative URLs always pass) and respect https when the request is secure.
    """
    if url and url_has_allowed_host_and_scheme(
            url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return url
    return fallback


def get_client_ip_address(request):
    # Number of trusted reverse-proxy hops in front of the app. The genuine client
    # IP is the Nth X-Forwarded-For entry counted from the right (the entries our
    # own proxies appended); anything further left is client-supplied and spoofable.
    proxy_count = getattr(settings, 'AUTHENTICATION_TRUSTED_PROXY_COUNT', 0)
    if not proxy_count and getattr(settings, 'BEHIND_REVERSE_PROXY', False):
        proxy_count = 1  # back-compat: the old boolean means a single trusted proxy
    if proxy_count:
        parts = [p.strip() for p in request.META.get('HTTP_X_FORWARDED_FOR', '').split(',') if p.strip()]
        if len(parts) >= proxy_count:
            return parts[-proxy_count]
        # Fewer hops than expected (proxy bypassed/misconfigured): fall back to the
        # immediate peer rather than trusting a short, possibly forged header.
    return request.META.get('REMOTE_ADDR')


def get_custom_auth():
    return import_string(getattr(settings, 'AUTHENTICATION_CUSTOMISATION', 'modal_2fa.customise.CustomiseAuth'))


DEFAULT_COOKIE_BACKEND_PATH = 'modal_2fa.auth.CookieBackend'


def get_cookie_backend_path():
    """Dotted path to record on the session when completing a login ourselves.

    ``django.contrib.auth.login()`` stores this path, and ``get_user()`` only
    restores the session if the stored path is listed in
    ``AUTHENTICATION_BACKENDS`` -- so it has to be the path the project actually
    registered. A project that subclasses ``CookieBackend`` (to scope it to a host
    or a schema, say) registers its own path, and hardcoding ours would silently
    log those users straight back out again.

    Returns the first ``AUTHENTICATION_BACKENDS`` entry that is a ``CookieBackend``
    subclass, falling back to our own path so behaviour is unchanged for the
    documented single-backend setup.
    """
    from .backends import CookieBackend   # here, not at module scope: backends imports this module

    for path in getattr(settings, 'AUTHENTICATION_BACKENDS', ()):
        try:
            backend = import_string(path)
        except ImportError:
            continue          # a broken entry is Django's problem to report, not ours
        if isinstance(backend, type) and issubclass(backend, CookieBackend):
            return path
    return DEFAULT_COOKIE_BACKEND_PATH
