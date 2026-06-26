import datetime

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.utils.html import escape, mark_safe

from django_modals.modals import Modal, TemplateModal
from django_modals.helper import modal_button, modal_button_method, show_modal

from .models import FailedLoginAttempt

UserModel = get_user_model()


class SuperuserModalMixin:
    """Restrict a modal to superusers.

    ``process_slug_kwargs`` is the permission hook ``BaseModalMixin.dispatch`` checks; returning
    ``False`` makes it raise ``ModalException`` instead of rendering the modal. The menus only show
    these modals to superusers, but this guards against a non-superuser hitting the URL directly.
    """

    def process_slug_kwargs(self):
        return self.request.user.is_superuser


class SecurityAdminModal(SuperuserModalMixin, TemplateModal):
    modal_template = 'modal_2fa/security_admin_modal.html'
    modal_title = 'Security Admin'
    size = 'xl'

    def modal_context(self):
        return {
            'failed_attempts': self.failed_attempt_rows(),
            'sessions': active_sessions(),
        }

    @staticmethod
    def failed_attempt_rows():
        now = datetime.datetime.now()
        rows = []
        for attempt in FailedLoginAttempt.objects.select_related('user').order_by('-locked_time', '-failed_attempts'):
            locked = bool(attempt.locked_time and attempt.locked_time > now)
            rows.append({
                'who': attempt.user.username if attempt.user_id else '',
                'ip': attempt.ip_address or '',
                'attempts': attempt.failed_attempts,
                'locked': locked,
                'locked_time': attempt.locked_time,
                'action': mark_safe(show_modal('auth:clear_lockout', 'pk', attempt.pk, button='Clear',
                                               button_classes='btn btn-sm btn-danger')),
            })
        return rows


def active_sessions():
    """Decode every unexpired session and pair it with its user.

    Relies on the database session backend (the default); a cache-only ``SESSION_ENGINE`` keeps no
    server-side session rows, so this list will be empty.
    """
    now = datetime.datetime.now()
    users = {str(u.pk): u for u in UserModel.objects.all()}
    rows = []
    for session in Session.objects.filter(expire_date__gte=now):
        data = session.get_decoded()
        user = users.get(data.get('_auth_user_id'))
        if user is None:
            continue
        rows.append({
            'who': user.username,
            'method': data.get('authentication_method', ''),
            'expires': session.expire_date,
            'action': mark_safe(show_modal('auth:force_logout', 'session', session.session_key, button='Sign out',
                                           button_classes='btn btn-sm btn-danger')),
        })
    rows.sort(key=lambda row: row['expires'], reverse=True)
    return rows


class ClearLockoutModal(SuperuserModalMixin, Modal):
    modal_title = 'Clear lockout'
    size = 'md'

    def attempt(self):
        return FailedLoginAttempt.objects.select_related('user').filter(pk=self.slug.get('pk')).first()

    def modal_content(self):
        attempt = self.attempt()
        if attempt is None:
            return '<p>This record no longer exists.</p>'
        who = escape(attempt.user.username) if attempt.user_id else f'IP address {escape(attempt.ip_address)}'
        return f'<p>Clear failed login attempts and remove any lockout for <b>{who}</b>?</p>'

    def get_modal_buttons(self):
        if self.attempt() is None:
            return [modal_button('Close', 'close', 'btn-secondary')]
        return [modal_button_method('Clear', 'confirm', 'btn-danger'),
                modal_button('Cancel', 'close', 'btn-secondary')]

    def button_confirm(self, **_kwargs):
        FailedLoginAttempt.objects.filter(pk=self.slug.get('pk')).delete()
        return self.command_response('reload')


class ForceLogoutModal(SuperuserModalMixin, Modal):
    modal_title = 'Sign out session'
    size = 'md'

    def session_object(self):
        return Session.objects.filter(session_key=self.slug.get('session')).first()

    def modal_content(self):
        session = self.session_object()
        if session is None:
            return '<p>This session no longer exists.</p>'
        user = UserModel.objects.filter(pk=session.get_decoded().get('_auth_user_id')).first()
        who = escape(user.username) if user else 'this user'
        return f'<p>End this session and sign out <b>{who}</b>?</p>'

    def get_modal_buttons(self):
        if self.session_object() is None:
            return [modal_button('Close', 'close', 'btn-secondary')]
        return [modal_button_method('Sign out', 'confirm', 'btn-danger'),
                modal_button('Cancel', 'close', 'btn-secondary')]

    def button_confirm(self, **_kwargs):
        Session.objects.filter(session_key=self.slug.get('session')).delete()
        return self.command_response('reload')
