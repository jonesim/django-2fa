from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.views import PasswordResetConfirmView, LoginView, PasswordResetView, PasswordChangeView
from django.db.models import ObjectDoesNotExist
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.template.loader import render_to_string

from django_otp.plugins.otp_totp.models import TOTPDevice

from django_modals.helper import modal_button_method, modal_button, ajax_modal_replace

from django_modals.modals import FormModal, Modal

from .backends import CookieBackend
from .models import RememberDeviceCookie
from .utils import get_client_ip_address, get_custom_auth
from .forms import CrispyPasswordChangeForm, CrispyPasswordResetForm, CrispySetPasswordForm, CrispyLoginForm, Form2FA,\
    RememberCookieForm

UserModel = get_user_model()


class CustomiseMixin:
    def __init__(self):
        super().__init__()
        self.customisation_class = get_custom_auth()(self)
        self.customisation_class.customise_view(self)


def auth_2fa_url(request):
    query_string = f'?next={request.GET["next"]}' if 'next' in request.GET else ''
    return reverse('auth:auth_2fa') + query_string


class SuccessRedirectMixin:

    request: WSGIRequest

    def success_response(self):
        if 'next' in self.request.GET:
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=self.request.GET['next'])
        elif self.request.POST.get('modal_type') == 'no-parent':
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=settings.LOGIN_REDIRECT_URL)
        else:
            # noinspection PyUnresolvedReferences
            return self.command_response('reload')

    def two_factor_response(self):
        if self.request.POST.get('modal_type') == 'no-parent':
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=auth_2fa_url(self.request))
        else:
            # noinspection PyUnresolvedReferences
            return self.modal_redirect('auth:auth_2fa')


class ResetPasswordModal(CustomiseMixin, FormModal, PasswordResetView):
    form_class = CrispyPasswordResetForm
    modal_title = 'Reset Password'
    success_url = '/'

    def form_valid(self, form):
        """
        from django.contrib.auth.models import User
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.encoding import force_bytes
        from django.utils.http import urlsafe_base64_encode
        user = User.objects.get(email=form.cleaned_data['email'])
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = reverse('password_reset_confirm', kwargs=dict(uidb64=uid, token=token))
        return self.command_response('redirect', url=reset_url)
        """
        self.html_email_template_name = self.customisation_class.reset_password_email_template
        self.email_template_name = self.customisation_class.reset_password_txt_email_template
        self.subject_template_name = self.customisation_class.reset_password_subject_template
        PasswordResetView.form_valid(self, form)
        return self.command_response('close')


class ModalPasswordResetView(CustomiseMixin, SuccessRedirectMixin, FormModal, PasswordResetConfirmView):
    form_class = CrispySetPasswordForm
    modal_title = 'Reset Password'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(message='Invalid/Expired Link', **kwargs)
        return context

    def form_valid(self, form):
        form.save()
        user_cache = authenticate(self.request, username=form.user.username,
                                  password=form.cleaned_data['new_password1'])
        if user_cache is None:
            return self.two_factor_response()
        auth_login(self.request, self.user)
        return self.success_response()


class UserInvite(ModalPasswordResetView):
    form_class = CrispySetPasswordForm
    modal_title = 'Set Password'

    @property
    def extra_context(self):
        return {'contents':
                mark_safe(f'<p>Welcome {self.user.username}</p>')}


class ConfirmCookieModal(CustomiseMixin, SuccessRedirectMixin, FormModal):

    form_class = RememberCookieForm
    modal_title = 'Name device'

    def form_valid(self, form):
        remember_cookie = RememberDeviceCookie(
            user=self.request.user, user_agent=self.request.headers['user-agent'],
            ip=get_client_ip_address(self.request), active=True, name=form.cleaned_data['name']
        )
        remember_cookie.save()
        response = self.success_response()
        remember_cookie.set_cookie(response)
        return response

    def get_context_data(self, **kwargs):
        footer = render_to_string(
            'modal_2fa/database_cookies.html',
            dict(cookies=RememberDeviceCookie.objects.filter(user=self.request.user, active=True))
        )
        self.extra_context = {'footer': mark_safe(f'<div class="modal-body">{footer}</div>')}
        context = super().get_context_data(**kwargs)
        return context

    def button_remove_device(self, **_kwargs):
        RememberDeviceCookie.objects.get(id=self.request.POST['id']).delete()
        return self.button_refresh_modal(whole_modal=True)


class UserDevices(CustomiseMixin, Modal):

    modal_title = 'Authorised Devices'

    def modal_content(self):
        cookies = RememberDeviceCookie.objects.filter(user=self.request.user, active=True)
        return render_to_string('modal_2fa/database_cookies.html', dict(no_title=True, cookies=cookies))

    def button_remove_device(self, **_kwargs):
        RememberDeviceCookie.objects.get(id=self.request.POST['id']).delete()
        return self.button_refresh_modal()


class Modal2FARemove(CustomiseMixin, Modal):

    def button_confirm(self, **_kwargs):
        device = TOTPDevice.objects.filter(user=self.request.user).first()
        if device:
            device.delete()
        RememberDeviceCookie.objects.filter(user=self.request.user).delete()
        self.request.session.pop('authentication_method', None)
        return self.command_response('reload')

    def get_modal_buttons(self):
        return [modal_button_method('Yes', 'confirm', 'btn-warning px-4'),
                modal_button('Cancel', 'close', 'btn-secondary')]

    def modal_content(self):
        return 'Are you sure you want to remove the protection of two-factor authentication?'


class Modal2FA(CustomiseMixin, SuccessRedirectMixin, FormModal):
    form_class = Form2FA
    modal_title = '2FA Code'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None

    def dispatch(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            self.user = self.request.user
        else:
            try:
                self.user = CookieBackend.get_part_login_user(request)
            except ObjectDoesNotExist:
                if not self.request.is_ajax():
                    return HttpResponseRedirect(reverse('auth:login'))
                return self.command_response('redirect', url=reverse('auth:login'))
        return super().dispatch(request, *args, **kwargs)

    def get_device(self):
        device = TOTPDevice.objects.filter(user=self.user).first()
        if self.request.method != 'POST' and device and not device.confirmed:
            device.delete()
            device = None
        if not device:
            device = TOTPDevice(user=self.user, confirmed=False)
            device.save()
        return device

    @staticmethod
    def allowed_remember(_user):
        # This can be subclassed from customise
        return True

    def get_form_kwargs(self):
        return dict(**super().get_form_kwargs(), request=self.request, device=self.get_device(),
                    allowed_remember=self.allowed_remember(self.user))

    def button_cancel(self, **_kwargs):
        del self.request.session[CookieBackend.part_login_key]
        auth_logout(self.request)
        self.add_command('close')
        return self.command_response('show_modal', modal=reverse('auth:login'))

    def form_valid(self, form):
        auth_login(self.request, self.user)
        if form.cleaned_data.get('remember'):
            return self.command_response(ajax_modal_replace(self.request, 'auth:confirm_remember',
                                                            modal_type=self.request.POST.get('modal_type')))
        return self.success_response()


class Change2FA(CustomiseMixin, SuccessRedirectMixin, FormModal):

    form_class = Form2FA
    modal_title = 'Change 2FA Code'

    def button_cancel(self, **_kwargs):
        return self.command_response('close')

    def form_valid(self, form):
        TOTPDevice.objects.filter(user=self.request.user, confirmed=True).exclude(id=form.device.id).delete()
        return self.command_response('close')

    def get_device(self):
        if self.request.method == 'POST':
            device = TOTPDevice.objects.filter(user=self.request.user, confirmed=False).first()
        else:
            TOTPDevice.objects.filter(user=self.request.user, confirmed=False).delete()
            device = TOTPDevice(user=self.request.user, confirmed=False)
            device.save()
        return device

    def get_form_kwargs(self):
        return dict(**super().get_form_kwargs(), request=self.request, device=self.get_device(), allowed_remember=False)


class ModalLoginView(CustomiseMixin, SuccessRedirectMixin, FormModal, LoginView):

    form_class = CrispyLoginForm
    modal_title = 'Sign In'
    no_header_x = True

    def button_logout(self, **_kwargs):
        auth_logout(self.request)
        return self.command_response('reload')

    def form_invalid(self, form):
        if CookieBackend.get_part_login(self.request):
            return self.two_factor_response()
        return super().form_invalid(form)

    def form_valid(self, form):
        LoginView.form_valid(self, form)
        response = self.success_response()
        RememberDeviceCookie.update_cookie(form.get_user(), self.request, response)
        return response


class ModalPasswordChangeView(CustomiseMixin, FormModal, PasswordChangeView):
    form_class = CrispyPasswordChangeForm
    modal_title = 'Change password'

    def form_valid(self, form):
        PasswordChangeView.form_valid(self, form)
        return self.command_response('reload')
