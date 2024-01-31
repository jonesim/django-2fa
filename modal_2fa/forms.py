from io import BytesIO
import qrcode
from django.templatetags.static import static

from qrcode.image.svg import SvgPathFillImage

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm, AuthenticationForm, PasswordResetForm, PasswordChangeForm
from django.forms import ValidationError, TextInput
from django.forms.fields import CharField, BooleanField
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe

from crispy_forms.layout import Field, HTML

from django_modals.helper import crispy_modal_link
from django_modals.forms import CrispyFormMixin, CrispyForm

from .utils import get_custom_auth
from .webauthn import web_authn_script

UserModel = get_user_model()


class CrispyPasswordResetForm(CrispyFormMixin, PasswordResetForm):
    pass


class CrispySetPasswordForm(CrispyFormMixin, SetPasswordForm):
    pass


class CrispyLoginForm(CrispyFormMixin, AuthenticationForm):

    def __init__(self, *args, locked=None, **kwargs):
        self.locked = locked
        super().__init__(*args, **kwargs)

    def post_init(self, *args, **kwargs):
        if self.locked:
            self.no_buttons = True
            return [HTML(f'<div class="alert alert-danger">{self.locked}</div>')]
        self.buttons.append(self.submit_button())
        return (
            Field('username', 'password'),
            crispy_modal_link('auth:reset_password', 'Forgot Password?', div=True, div_classes='text-center'),
        )


class Form2FA(CrispyForm):

    class Meta:
        modal_title = '2FA Code'

    code = CharField(widget=TextInput(attrs={'autocomplete': 'off'}))
    remember = BooleanField(label='Remember device', required=False)

    @staticmethod
    def get_qr_code(device):
        img = qrcode.make(device.config_url, image_factory=SvgPathFillImage)
        svg = BytesIO()
        img.save(svg)
        svg.seek(0)
        return mark_safe(svg.read().decode('UTF-8'))

    def post_init(self, *args, **kwargs):
        self.buttons = []
        if not self.device.confirmed:
            new_device = (HTML(render_to_string('modal_2fa/new_totp.html', {'svg': self.get_qr_code(self.device)})),
                          HTML(web_authn_script))
        else:
            new_device = (HTML(web_authn_script),)
        self.buttons += [self.submit_button(),
                        self.button('Cancel', dict(function='post_modal', button='cancel'), self.cancel_class)]
        if not self.allowed_remember:
            # noinspection PyTypeChecker
            del self.fields['remember']
            return *new_device, Field('code')
        else:
            return *new_device, Field('code', 'remember')

    def clean(self):
        super(Form2FA, self).clean()
        if 'code' in self.cleaned_data:
            if not authenticate(self.request, device=self.device, token=self.cleaned_data['code']):
                raise ValidationError('Incorrect Code')
            else:
                self.device.confirmed = True
                self.device.save()
        return self.cleaned_data

    def __init__(self, request, device, *args, allowed_remember=True, **kwargs):
        self.request = request
        self.device = device
        self.allowed_remember = allowed_remember
        super(Form2FA, self).__init__(*args, **kwargs)


class RememberCookieForm(CrispyForm):
    class Meta:
        modal_title = 'Name Device'

    name = CharField()

    def post_init(self, *args, **kwargs):
        self.buttons.append(self.submit_button())
        self.buttons.append(self.button('Cancel', 'reload', self.cancel_class))
        return (Field('name'), HTML('<div class="alert alert-block alert-warning">'
                                    'Warning this will bypass two-factor authorisation in the future '
                                    'for this device</div>'))

    def clean(self):
        if get_custom_auth().max_cookies_already(self.user):
            raise ValidationError('Too many authorised devices. Please remove one')


class CrispyPasswordChangeForm(CrispyFormMixin, PasswordChangeForm):
    pass
