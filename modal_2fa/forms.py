from io import BytesIO
import qrcode
from qrcode.image.svg import SvgImage

from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm, AuthenticationForm, PasswordResetForm, PasswordChangeForm
from django.forms import ValidationError
from django.forms.fields import CharField, BooleanField
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe

from crispy_forms.layout import Field, HTML

from django_modals.helper import crispy_modal_link
from django_modals.forms import CrispyFormMixin, CrispyForm


UserModel = get_user_model()


class CrispyPasswordResetForm(CrispyFormMixin, PasswordResetForm):
    pass


class CrispySetPasswordForm(CrispyFormMixin, SetPasswordForm):
    pass


class CrispyLoginForm(CrispyFormMixin, AuthenticationForm):

    def post_init(self, *args, **kwargs):
        self.buttons.append(self.submit_button())

        return (Field('username', 'password'),
                crispy_modal_link('reset_password_modal', 'Forgot Password?', div=True, div_classes='text-center'),
                )


class Form2FA(CrispyForm):

    class Meta:
        modal_title = '2FA Code'

    code = CharField()
    remember = BooleanField(label='Remember device', required=False)

    @staticmethod
    def get_qr_code(device):
        img = qrcode.make(device.config_url, image_factory=SvgImage)
        svg = BytesIO()
        img.save(svg)
        svg.seek(0)
        return mark_safe(svg.read().decode('UTF-8'))

    def post_init(self, *args, **kwargs):

        if not self.device.confirmed:
            new_device = (HTML(render_to_string('modal_2fa/new_topt.html',
                                                {'svg': self.get_qr_code(self.device)})),)
        else:
            new_device = ()
        self.buttons = [self.submit_button(),
                        self.button('Cancel', dict(function='post_modal', button='logout'), self.cancel_class)]
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

    def __init__(self, request, device, *args, **kwargs):
        self.request = request
        self.device = device
        super(Form2FA, self).__init__(*args, **kwargs)


class RememberCookieForm(CrispyForm):
    class Meta:
        modal_title = 'Name Device'

    name = CharField()

    def post_init(self, *args, **kwargs):
        self.buttons.append(self.submit_button())
        self.buttons.append(self.button('Cancel', 'reload', self.cancel_class))
        return (Field('name'), HTML('<div class="text-center"><span class="badge badge-danger">'
                                    'Warning this will bypass two-factor authorisation in the future '
                                    'for this device</span></div>'))


class CrispyPasswordChangeForm(CrispyFormMixin, PasswordChangeForm):
    pass
