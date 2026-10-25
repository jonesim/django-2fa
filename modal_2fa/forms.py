from io import BytesIO
import qrcode

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
from .microsoft import microsoft_configured, microsoft_login_button
from .webauthn import web_authn_script

UserModel = get_user_model()


class CrispyPasswordResetForm(CrispyFormMixin, PasswordResetForm):
    pass


class CrispySetPasswordForm(CrispyFormMixin, SetPasswordForm):
    pass


class CrispyLoginForm(CrispyFormMixin, AuthenticationForm):

    def __init__(self, *args, locked=None, sso_only=None, **kwargs):
        self.locked = locked
        self.sso_only = sso_only
        super().__init__(*args, **kwargs)

    def post_init(self, *args, **kwargs):
        if self.locked:
            self.no_buttons = True
            return [HTML(f'<div class="alert alert-danger">{self.locked}</div>')]
        if self.sso_only:
            # Entra-only account: no password fields or submit button -- just the
            # explanation and the Microsoft sign-in button (the only way in).
            self.no_buttons = True
            return [HTML(f'<div class="alert alert-warning">{self.sso_only}</div>'),
                    HTML(microsoft_login_button())]
        self.buttons.append(self.submit_button())
        layout = [
            Field('username', 'password'),
            crispy_modal_link('auth:reset_password', 'Forgot Password?', div=True, div_classes='text-center'),
        ]
        if microsoft_configured():
            # Full-page navigation (OAuth needs a real redirect), not an AJAX modal command.
            layout.append(HTML(microsoft_login_button()))
        return tuple(layout)


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
        if self.locked:
            # Account/IP is locked out: render only the alert, no code field or
            # submit button. Enforcement is in clean() -- this is just the UI.
            self.no_buttons = True
            return (HTML(f'<div class="alert alert-danger">{self.locked}</div>'),)
        cancel = self.button('Cancel', dict(function='post_modal', button='cancel'), self.cancel_class)
        if self.factor_mode == 'choice':
            # First-time setup: no fields at all -- either factor is set up via
            # its own button and clean() refuses anything else.
            del self.fields['code']
            del self.fields['remember']
            if self.allow_passkeys:
                self.buttons.append(self.button('Set up a passkey',
                                                dict(function='post_modal', button='setup_passkey'), 'btn-primary'))
            if self.allow_totp:
                self.buttons.append(self.button('Use an authenticator app',
                                                dict(function='post_modal', button='setup_totp'), 'btn-outline-secondary'))
            self.buttons.append(cancel)
            return (HTML(render_to_string('modal_2fa/2fa_choice.html', {'allow_passkeys': self.allow_passkeys,
                                                                        'allow_totp': self.allow_totp})),
                    HTML(web_authn_script()))
        if self.factor_mode == 'passkey_only':
            # Verification for a user whose only factor is a passkey: the
            # browser prompt fires on load; the button re-fires it after a
            # cancel or timeout. No code field, so nothing to submit.
            del self.fields['code']
            del self.fields['remember']
            self.buttons += [self.button('Use passkey',
                                         dict(function='post_modal', button='use_passkey'), 'btn-primary'),
                             cancel]
            return (HTML(render_to_string('modal_2fa/passkey_prompt.html')), HTML(web_authn_script()))
        if self.factor_mode == 'totp_new':
            layout = (HTML(render_to_string('modal_2fa/new_totp.html', {'svg': self.get_qr_code(self.device)})),)
            self.buttons.append(self.submit_button())
            if self.back_button:
                self.buttons.append(self.button('Back', dict(function='post_modal', button='setup_back'),
                                                'btn-outline-secondary'))
        else:
            layout = (HTML(web_authn_script()),)
            self.buttons.append(self.submit_button())
            if self.has_passkey:
                self.buttons.append(self.button('Use passkey',
                                                dict(function='post_modal', button='use_passkey'),
                                                'btn-outline-primary'))
        self.buttons.append(cancel)
        if not self.allowed_remember:
            # noinspection PyTypeChecker
            del self.fields['remember']
            return *layout, Field('code')
        else:
            return *layout, Field('code', 'remember')

    def clean(self):
        super(Form2FA, self).clean()
        if self.locked:
            # Server-side guard: reject even a crafted POST carrying a code while
            # locked, regardless of what post_init chose to render.
            raise ValidationError(self.locked)
        if self.factor_mode not in ('totp', 'totp_new'):
            # The code field is deleted in the other modes, so an empty POST
            # would otherwise validate and reach form_valid -> auth_login with
            # no second factor at all.
            raise ValidationError('Choose a verification method')
        if 'code' not in self.cleaned_data:
            raise ValidationError('Enter code')
        if not authenticate(self.request, device=self.device, token=self.cleaned_data['code']):
            raise ValidationError('Incorrect Code')
        self.device.confirmed = True
        self.device.save()
        return self.cleaned_data

    def __init__(self, request, device=None, *args, mode='totp', allowed_remember=True, locked=None,
                 has_passkey=False, back_button=False, allow_passkeys=True, allow_totp=True, **kwargs):
        self.request = request
        self.device = device
        self.factor_mode = mode
        self.allowed_remember = allowed_remember
        self.locked = locked
        self.has_passkey = has_passkey
        self.back_button = back_button
        self.allow_passkeys = allow_passkeys
        self.allow_totp = allow_totp
        super(Form2FA, self).__init__(*args, **kwargs)


class PasskeyNameForm(CrispyForm):
    class Meta:
        modal_title = 'Name passkey'

    name = CharField(max_length=60, label='Name')

    def post_init(self, *args, **kwargs):
        self.buttons.append(self.submit_button())
        self.buttons.append(self.button('Skip', dict(function='post_modal', button='cancel'), self.cancel_class))
        return (HTML('<p>Passkey added. Give it a name so you can recognise it later '
                     '(e.g. "Work laptop" or "iPhone").</p>'),
                Field('name'))


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
