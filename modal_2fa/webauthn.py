import json

from ajax_helpers.mixins import ajax_method
from django.conf import settings
from django.utils import timezone
from django.templatetags.static import static

from ajax_helpers.utils import ajax_command
from webauthn.helpers import bytes_to_base64url

from modal_2fa.models import WebauthnCredential

web_authn_script = f'<script src="{static("modal_2fa/webauthn.js")}"></script>'

try:
    from webauthn import (generate_registration_options, options_to_json, verify_registration_response,
                          base64url_to_bytes, generate_authentication_options, verify_authentication_response)
    from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement

    not_installed = False
except ModuleNotFoundError:
    not_installed = True


def get_rp_id():
    return getattr(settings, 'WEBAUTHN_RP_ID', 'localhost')


def get_user_authenticators(user):
    return user.webauthn.filter(rp_id=get_rp_id())


class WebAuthnMixin:

    rp_name = ''

    def __init__(self, *args, **kwargs):
        self.last_error = None
        self.rp_id = get_rp_id()
        self.rp_name = getattr(settings, 'WEBAUTHN_RP_NAME', self.rp_id)
        super().__init__(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        if hasattr(self, 'user'):
            authenticators = get_user_authenticators(self.user)
            if authenticators:
                self.ask_for_credentials(authenticators)
        return super().get(request, *args, **kwargs)

    def ask_for_credentials(self, authenticators):
        if not_installed:
            return
        allowed_credentials = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(credentials.credential_id))
                               for credentials in authenticators]
        authentication_options = generate_authentication_options(
            rp_id=self.rp_id,
            user_verification=UserVerificationRequirement.DISCOURAGED,
            allow_credentials=allowed_credentials
        )
        self.save_challenge(authentication_options.challenge)
        self.page_commands = [ajax_command('authenticate', authentication=options_to_json(authentication_options))]

    def registration_command(self, user):
        public_credential_creation_options = generate_registration_options(
            rp_id=self.rp_id,
            user_id=str(user.pk).rjust(16, '0').encode('ascii'),
            user_name=user.username,
            rp_name=self.rp_name
        )
        self.save_challenge(public_credential_creation_options.challenge)
        return ajax_command('register_authentication', creation=options_to_json(public_credential_creation_options))

    def register_credential(self, user):
        try:
            authentication_verification = verify_registration_response(
                credential=self.request.POST['data'],
                expected_challenge=self.get_challenge(),
                expected_origin=self.get_origin(),
                expected_rp_id=self.rp_id,
            )
            WebauthnCredential.objects.create(
                user=user,
                rp_id=self.rp_id,
                credential_public_key=bytes_to_base64url(authentication_verification.credential_public_key),
                credential_id=bytes_to_base64url(authentication_verification.credential_id),
                sign_count=authentication_verification.sign_count
            )
        except InvalidRegistrationResponse as error:
            self.last_error = error
            return False
        return True

    def get_origin(self):
        if not self.request.is_secure() and self.request.get_host().startswith('localhost'):
            return 'http://' + self.request.get_host()
        return 'https://' + self.request.get_host()

    def save_challenge(self, challenge):
        self.request.session['auth_challenge'] = challenge.hex()

    def get_challenge(self):
        return bytearray.fromhex(self.request.session['auth_challenge'])

    def check_authentication(self, user):

        try:
            response = json.loads(self.request.POST.get('data'))
            credentials = WebauthnCredential.objects.filter(user=user, credential_id=response['id'],
                                                            rp_id=self.rp_id).first()
            authentication_verification = verify_authentication_response(
                credential=response,
                expected_challenge=self.get_challenge(),
                expected_origin=self.get_origin(),
                expected_rp_id=self.rp_id,
                credential_public_key=base64url_to_bytes(credentials.credential_public_key),
                credential_current_sign_count=0
            )
            credentials.sign_count = authentication_verification.new_sign_count
            credentials.last_used_on = timezone.now()
            credentials.save()
        except InvalidAuthenticationResponse as error:
            self.last_error = error
            return False
        return True

    @ajax_method
    def error(self, data, **_kwargs):
        return self.error_message(f'Error logging in with credential<br>{data}')

    @ajax_method
    def register(self, **_kwargs):
        if not self.register_credential(self.request.user):
            return self.error_message(f'Error registering credential<br>{self.last_error}')
        return self.command_response('close')
