from io import BytesIO
import qrcode
from qrcode.image.svg import SvgImage

from django.conf import settings
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import PasswordResetConfirmView, LoginView, PasswordResetView, PasswordChangeView
from django.db.models import ObjectDoesNotExist
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.template.loader import render_to_string

from django_otp.plugins.otp_totp.models import TOTPDevice

from django_modals.helper import modal_button_method, modal_button, ajax_modal_replace

from django_modals.modals import FormModal, Modal

from .backends import CookieBackend
from .models import RememberDeviceCookie
from .utils import get_client_ip_address
from .forms import CrispyPasswordChangeForm, CrispyPasswordResetForm, CrispySetPasswordForm, CrispyLoginForm, Form2FA,\
    RememberCookieForm

UserModel = get_user_model()


class SuccessRedirectMixin:

    def success_response(self):
        # noinspection PyUnresolvedReferences
        if self.request.POST.get('modal_type') == 'no-parent':
            # noinspection PyUnresolvedReferences
            return self.command_response('redirect', url=settings.LOGIN_REDIRECT_URL)
        else:
            # noinspection PyUnresolvedReferences
            return self.command_response('reload')


class ResetPasswordModal(FormModal, PasswordResetView):
    form_class = CrispyPasswordResetForm
    modal_title = 'Reset Password'

    def form_valid(self, form):
        user = User.objects.get(email=form.cleaned_data['email'])
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_url = reverse('password_reset_confirm', kwargs=dict(uidb64=uid, token=token))
        return self.command_response('redirect', url=reset_url)


class ModalPasswordResetView(FormModal, PasswordResetConfirmView):
    form_class = CrispySetPasswordForm
    modal_title = 'Reset Password'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(message='Invalid/Expired Link', **kwargs)
        return context

    def form_valid(self, form):
        PasswordResetConfirmView.form_valid(self, form)
        return self.command_response('close')


class ConfirmCookieModal(SuccessRedirectMixin, FormModal):

    form_class = RememberCookieForm

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
        self.extra_context = {'footer': mark_safe(render_to_string(
            'modal_2fa/database_cookies.html',
            dict(cookies=RememberDeviceCookie.objects.filter(user=self.request.user, active=True))))}
        context = super().get_context_data(**kwargs)
        return context


class UserDevices(Modal):

    modal_title = 'Current Registered Devices'

    def modal_content(self):
        cookies = RememberDeviceCookie.objects.filter(user=self.request.user, active=True)
        return render_to_string('modal_2fa/database_cookies.html', dict(no_title=True, cookies=cookies))

    def button_remove_device(self, **kwargs):
        RememberDeviceCookie.objects.get(id=kwargs['id']).delete()
        return self.command_response(ajax_modal_replace(self.request, modal_class=UserDevices))


class Modal2FARemove(Modal):

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


class Modal2FA(SuccessRedirectMixin, FormModal):
    form_class = Form2FA

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
                    return HttpResponseRedirect(reverse('login_modal'))
                return self.command_response('redirect', url=reverse('login_modal'))
        return super().dispatch(request, *args, **kwargs)

    def get_device(self):
        if self.slug.get('action') != 'change':
            device = TOTPDevice.objects.filter(user=self.user).first()
            if self.request.method != 'POST' and device and not device.confirmed:
                device.delete()
                device = None
        else:
            if self.request.method == 'POST':
                device = TOTPDevice.objects.filter(user=self.user, confirmed=False).first()
            else:
                TOTPDevice.objects.filter(user=self.user, confirmed=False).delete()
                device = None
        if not device:
            device = TOTPDevice(user=self.user, confirmed=False)
            device.save()
        return device

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['request'] = self.request
        kwargs['device'] = self.get_device()
        return kwargs

    def button_logout(self, **_kwargs):
        del self.request.session[CookieBackend.part_login_key]
        auth_logout(self.request)
        self.add_command('close')
        return self.command_response('show_modal', modal=reverse('login_modal'))

    def form_valid(self, form):
        if self.slug.get('action') == 'change':
            TOTPDevice.objects.filter(user=self.user, confirmed=True).exclude(id=form.device.id).delete()
        auth_login(self.request, self.user)
        if form.cleaned_data.get('remember'):
            return self.command_response(ajax_modal_replace(self.request, 'confirm_remember',
                                                            modal_type=self.request.POST.get('modal_type')))
        return self.success_response()

    @staticmethod
    def get_qr_code(device):
        img = qrcode.make(device.config_url, image_factory=SvgImage)
        svg = BytesIO()
        img.save(svg)
        svg.seek(0)
        return mark_safe(svg.read().decode('UTF-8'))


class ModalLoginView(SuccessRedirectMixin, FormModal, LoginView):

    form_class = CrispyLoginForm
    modal_title = 'Sign In'
    no_header_x = True

    def button_logout(self, **_kwargs):
        auth_logout(self.request)
        return self.command_response('reload')

    def form_invalid(self, form):
        if CookieBackend.get_part_login(self.request):
            if self.request.POST.get('modal_type') == 'no-parent':
                return self.command_response('redirect', url=reverse('auth_2fa'))
            else:
                return self.modal_redirect('auth_2fa')
        return super().form_invalid(form)

    def form_valid(self, form):
        LoginView.form_valid(self, form)
        response = self.success_response()
        RememberDeviceCookie.update_cookie(form.get_user(), self.request, response)
        return response


class ModalPasswordChangeView(FormModal, PasswordChangeView):
    form_class = CrispyPasswordChangeForm
    modal_title = 'Change password'

    def form_valid(self, form):
        PasswordChangeView.form_valid(self, form)
        return self.command_response('reload')
