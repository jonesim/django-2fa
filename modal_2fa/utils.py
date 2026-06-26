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
