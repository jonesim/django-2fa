from ajax_helpers.mixins import AjaxHelpers
from django.conf import settings
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import PasswordResetView
from django.views import View

from django_modals.modals import ModelFormModal, Modal
from django_modals.helper import modal_button, modal_button_method
from django_modals.processes import PERMISSION_METHOD

from django.utils.html import escape
from django.utils.safestring import mark_safe

from .auth import CustomiseMixin, describe_second_factors, remove_second_factors
from .models import FailedLoginAttempt
from .notify import notify_security_change, TWO_FACTOR_RESET
from .utils import get_custom_auth

UserModel = get_user_model()


class UserAdminPermissionMixin:
    """Gate a user-management modal behind ``CustomiseAuth.can_manage_users``.

    For simple ``Modal``/``TemplateModal`` views whose ``process_slug_kwargs``
    otherwise just returns ``True`` (open). These modals are registered
    unconditionally under ``auth/``, so without this an unauthenticated request
    could reach them. Mirrors the hook the user menu already checks (see
    ``menus.py``).

    Not for ``ModelFormModal`` — that resolves permissions from its
    ``permission_*`` attributes inside its own ``process_slug_kwargs`` (which
    also sets up the object/process), so overriding the method there would skip
    that setup. Use ``PERMISSION_METHOD`` + ``permission()`` for those instead.
    """

    def process_slug_kwargs(self):
        return get_custom_auth().can_manage_users(self.request.user, self.request)


class UserAdminViewPermissionMixin(UserPassesTestMixin):
    """Gate a plain (non-modal) view behind ``CustomiseAuth.can_manage_users``.

    ``DatatableView`` is a bare ``TemplateView`` with no ``process_slug_kwargs``
    hook, so ``UserAdminPermissionMixin`` would be silently inert on it.
    ``handle_no_permission`` sends anonymous users to the login page and raises
    ``PermissionDenied`` for anyone already signed in.
    """

    def test_func(self):
        return get_custom_auth().can_manage_users(self.request.user, self.request)


class ModalUserForm(ModelFormModal):

    model = UserModel
    form_fields = ['email', 'first_name', 'last_name']

    # ModelFormModal resolves permission from these attributes; PERMISSION_METHOD
    # routes each process (create/edit/view) through permission() below.
    permission_create = PERMISSION_METHOD
    permission_edit = PERMISSION_METHOD
    permission_view = PERMISSION_METHOD

    def permission(self, user, process):
        # ``self`` is None when django-modals resolves permission at class level
        # (ModelFormModal.user_has_perm), so there is no request to hand on.
        return get_custom_auth().can_manage_users(user, getattr(self, 'request', None))

    def form_valid(self, form):
        self.object.username = self.object.email
        return super().form_valid(form)

    def create_object(self):
        return self.modal_replace('invite_user_confirm', slug=str(self.object.id))


class ModalInviteUser(UserAdminPermissionMixin, CustomiseMixin, Modal, PasswordResetView):
    success_url = '/'
    modal_title = 'Send Email Invite to user'

    @property
    def user(self):
        return UserModel.objects.get(id=self.kwargs['pk'])

    def modal_content(self):
        user = self.user
        return (f'<table class="table"><tr><td><b>User</b></td><td>{user.first_name} {user.last_name}</td>'
                f'</tr><tr><td><b>Email</b></td><td>{user.email}</td></tr></table>')

    def get_modal_buttons(self):
        return [modal_button_method('Confirm', 'confirm'), modal_button('Cancel', 'close', 'btn-secondary')]

    def button_confirm(self, **_kwargs):
        self.html_email_template_name = self.customisation_class.invite_email_template
        self.email_template_name = self.customisation_class.invite_txt_email_template
        self.subject_template_name = self.customisation_class.invite_subject_template
        form = PasswordResetForm(data={'email': self.user.email})
        form.is_valid()
        self.form_valid(form)
        return self.command_response('close')


class ModalResetUser2FA(UserAdminPermissionMixin, CustomiseMixin, Modal):
    """Administrator reset for a user who has lost their second factor: strips
    every TOTP device, passkey and trusted device so they go through first-time
    setup at their next sign-in, and clears their lockout (a locked-out user is
    usually why an administrator is here). The user is emailed."""

    modal_title = 'Reset 2FA'
    size = 'md'

    @property
    def user(self):
        return UserModel.objects.get(id=self.kwargs['pk'])

    def modal_content(self):
        user = self.user
        removals = describe_second_factors(user)
        who = f'<b>{escape(user.get_username())}</b>'
        if not removals:
            return mark_safe(f'{who} has no second factor or trusted device. '
                             f'Resetting will only clear any lockout on the account.')
        return mark_safe(f'Reset two-factor authentication for {who}?<br>'
                         f'This will remove {", ".join(removals).replace("your ", "their ")}. '
                         f'They will be asked to set up 2FA again when they next sign in.')

    def get_modal_buttons(self):
        return [modal_button_method('Reset', 'confirm', 'btn-danger'),
                modal_button('Cancel', 'close', 'btn-secondary')]

    def button_confirm(self, **_kwargs):
        user = self.user
        remove_second_factors(user)
        FailedLoginAttempt.objects.filter(user=user).delete()
        notify_security_change(self.request, user, TWO_FACTOR_RESET)
        return self.command_response('reload')


class LogoutUser(AjaxHelpers, View):

    def post(self, request, **kwargs):
        logout(request)
        if settings.LOGOUT_REDIRECT_URL:
            return self.command_response('redirect', url=settings.LOGOUT_REDIRECT_URL)
        else:
            return self.command_response('reload')
