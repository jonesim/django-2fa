"""Email a user when something about their sign-in security changes.

A second factor or trusted device being added or removed, 2FA being removed or
reset, a password change: the account owner should hear about each one, so a
change they didn't make is noticed instead of discovered at the next sign-in.

The views call ``notify_security_change``; it hands off to
``CustomiseAuth.notify_security_change`` (override it to reword, log, raise a
signal or route elsewhere) and never raises -- a mail failure must not roll
back or 500 the change it reports.
"""
import logging

from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone

from .utils import get_client_ip_address, get_custom_auth

logger = logging.getLogger('modal_2fa')

PASSKEY_ADDED = 'passkey_added'
PASSKEY_REMOVED = 'passkey_removed'
TOTP_ENROLLED = 'totp_enrolled'
TOTP_CHANGED = 'totp_changed'
TRUSTED_DEVICE_ADDED = 'trusted_device_added'
TRUSTED_DEVICE_REMOVED = 'trusted_device_removed'
TWO_FACTOR_REMOVED = 'two_factor_removed'
TWO_FACTOR_RESET = 'two_factor_reset'
PASSWORD_CHANGED = 'password_changed'

# ``{name}`` is the passkey / device name, rendered as ' "Work laptop"' or ''.
SECURITY_EVENTS = {
    PASSKEY_ADDED: 'A passkey{name} was added to your account.',
    PASSKEY_REMOVED: 'A passkey{name} was removed from your account.',
    TOTP_ENROLLED: 'An authenticator app was set up for your account.',
    TOTP_CHANGED: 'The authenticator app for your account was changed. Codes from the old app no longer work.',
    TRUSTED_DEVICE_ADDED: 'A trusted device{name} was added to your account. '
                          'It will skip two-factor authentication when signing in.',
    TRUSTED_DEVICE_REMOVED: 'A trusted device{name} was removed from your account.',
    TWO_FACTOR_REMOVED: 'Two-factor authentication was removed from your account.',
    TWO_FACTOR_RESET: 'Two-factor authentication on your account was reset by an administrator. '
                      'You will be asked to set it up again when you next sign in.',
    PASSWORD_CHANGED: 'The password for your account was changed.',
}


def event_message(event, name=None, events=None):
    template = (events or SECURITY_EVENTS).get(event)
    if template is None:
        raise ValueError(f'Unknown security event {event!r}')
    return template.format(name=f' "{name}"' if name else '')


def security_change_context(request, user, event, message):
    # get_current_site falls back to the request's host when the sites app
    # isn't installed, as PasswordResetView does.
    site = get_current_site(request)
    return {
        'user': user,
        'event': event,
        'message': message,
        'site_name': site.name,
        'domain': site.domain,
        'protocol': 'https' if request.is_secure() else 'http',
        'ip': get_client_ip_address(request),
        'user_agent': request.headers.get('user-agent', ''),
        'when': timezone.now(),
    }


def send_security_change_email(request, user, event, message, subject_template, txt_template, html_template=None):
    context = security_change_context(request, user, event, message)
    # One line, as Django's password reset does.
    subject = ''.join(render_to_string(subject_template, context).splitlines())
    body = render_to_string(txt_template, context)
    html = render_to_string(html_template, context) if html_template else None
    send_mail(subject, body, None, [user.email], html_message=html)


def notify_security_change(request, user, event, name=None):
    """Tell ``user`` that ``event`` happened to their account. ``name`` is the
    passkey or trusted-device name where there is one. Logs and swallows any
    failure: the change has already been made."""
    try:
        get_custom_auth().notify_security_change(request, user, event, name=name)
    except Exception:   # noqa: BLE001 -- deliberately broad, see docstring
        logger.exception('Security notification %r for user %s failed', event, user.pk)
