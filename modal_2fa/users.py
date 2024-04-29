from ajax_helpers.mixins import AjaxHelpers
from django.conf import settings
from django.contrib.auth import get_user_model, logout
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.views import PasswordResetView
from django.views import View

from django_modals.modals import ModelFormModal, Modal
from django_modals.helper import modal_button, modal_button_method

from .auth import CustomiseMixin

UserModel = get_user_model()


class ModalUserForm(ModelFormModal):

    model = UserModel
    form_fields = ['email', 'first_name', 'last_name']

    def form_valid(self, form):
        self.object.username = self.object.email
        return super().form_valid(form)

    def create_object(self):
        return self.modal_replace('invite_user_confirm', slug=str(self.object.id))


class ModalInviteUser(CustomiseMixin, Modal, PasswordResetView):
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


class LogoutUser(AjaxHelpers, View):

    def post(self, request, **kwargs):
        logout(request)
        if settings.LOGOUT_REDIRECT_URL:
            return self.command_response('redirect', url=settings.LOGOUT_REDIRECT_URL)
        else:
            return self.command_response('reload')
