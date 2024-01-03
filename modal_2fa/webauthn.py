import json
from django.utils import timezone

from ajax_helpers.utils import ajax_command

from modal_2fa.models import WebauthnCredentials

try:
    from webauthn import (generate_registration_options, options_to_json, verify_registration_response,
                          base64url_to_bytes, generate_authentication_options, verify_authentication_response)
    from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    not_installed = False
except ModuleNotFoundError:
    not_installed = True


class WebAuthnMixin:

    rp_id = 'localhost'
    rp_name = ''

    def __init__(self, *args, **kwargs):
        self.last_error = None
        super().__init__(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        if hasattr(self, 'user'):
            authenticators = self.user.webauthn.all()
            if authenticators:
                self.ask_for_credentials(authenticators)
        return super().get(request, *args, **kwargs)

    def ask_for_credentials(self, authenticators):
        if not_installed:
            return
        allowed_credentials = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(credentials.credential_id))
                               for credentials in authenticators]
        authentication_options = generate_authentication_options(rp_id=self.rp_id,
                                                                 user_verification='discouraged',
                                                                 allow_credentials=allowed_credentials)
        self.save_challenge(authentication_options.challenge)
        self.page_commands = [ajax_command('authenticate', authentication=options_to_json(authentication_options))]

    def registration_command(self, user):
        public_credential_creation_options = generate_registration_options(
            rp_id=self.rp_id,
            user_id=str(user.pk),
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
            auth_json = json.loads(authentication_verification.model_dump_json())
            WebauthnCredentials.objects.create(
                user=user,
                credential_public_key=auth_json.get("credential_public_key"),
                credential_id=auth_json.get("credential_id"),
                sign_count=authentication_verification.sign_count
            )
        except InvalidRegistrationResponse as error:
            self.last_error = error
            return False
        return True

    def get_origin(self):
        return ('https://' if self.request.is_secure() else 'http://') + self.request.get_host()

    def save_challenge(self, challenge):
        self.request.session['auth_challenge'] = challenge.hex()

    def get_challenge(self):
        return bytearray.fromhex(self.request.session['auth_challenge'])

    def check_authentication(self, user):

        try:
            response = json.loads(self.request.POST.get('data'))
            credentials = WebauthnCredentials.objects.filter(user=user, credential_id=response['id']).first()
            authentication_verification = verify_authentication_response(
                credential=response,
                expected_challenge=self.get_challenge(),
                expected_origin=self.get_origin(),
                expected_rp_id=self.rp_id,
                credential_public_key=base64url_to_bytes(credentials.credential_public_key),
                credential_current_sign_count=0
            )
            credentials.sign_count = authentication_verification.new_sign_count
            credentials.last_used_at = timezone.now()
            credentials.save()
        except InvalidAuthenticationResponse as error:
            self.last_error = error
            return False
        return True
