import json

from ajax_helpers.mixins import ajax_method
from django.conf import settings
from django.utils import timezone
from django.templatetags.static import static

from ajax_helpers.utils import ajax_command
from webauthn.helpers import bytes_to_base64url

from modal_2fa.models import WebauthnCredential


def web_authn_script():
    try:
         return f'<script src="{static("modal_2fa/webauthn.js")}"></script>'
    except ValueError:
        return ''

try:
    from webauthn import (generate_registration_options, options_to_json, verify_registration_response,
                          base64url_to_bytes, generate_authentication_options, verify_authentication_response)
    from webauthn.helpers.exceptions import (InvalidRegistrationResponse, InvalidAuthenticationResponse,
                                             InvalidJSONStructure)
    from webauthn.helpers.structs import (PublicKeyCredentialDescriptor, UserVerificationRequirement,
                                          AuthenticatorSelectionCriteria, ResidentKeyRequirement,
                                          AuthenticatorTransport)

    not_installed = False
except ModuleNotFoundError:
    not_installed = True


def get_rp_id():
    return getattr(settings, 'WEBAUTHN_RP_ID', 'localhost')


def get_user_authenticators(user):
    return user.webauthn.filter(rp_id=get_rp_id())


def user_has_passkey(user):
    # rp_id-scoped on purpose: a credential registered for another deployment
    # can't be asserted here, so counting it would strand the user with no
    # usable second factor.
    return get_user_authenticators(user).exists()


def user_may_use_passkeys(user):
    from modal_2fa.utils import get_custom_auth
    return not not_installed and get_custom_auth().allow_passkeys(user)


def credential_transports(response):
    # Client-supplied: keep only strings, so a null or odd-shaped list stores
    # nothing rather than raising.
    transports = (response.get('response') or {}).get('transports')
    if not isinstance(transports, list):
        return ''
    return ','.join(t for t in transports if isinstance(t, str))[:120]


def credential_descriptor(credential):
    transports = [AuthenticatorTransport(t) for t in credential.transport_list()
                  if t in AuthenticatorTransport._value2member_map_]
    return PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential.credential_id),
                                         transports=transports or None)


class WebAuthnMixin:

    rp_name = ''

    def __init__(self, *args, **kwargs):
        self.last_error = None
        self.rp_id = get_rp_id()
        self.rp_name = getattr(settings, 'WEBAUTHN_RP_NAME', self.rp_id)
        super().__init__(*args, **kwargs)

    def user_verification(self):
        from modal_2fa.utils import get_custom_auth
        return UserVerificationRequirement(get_custom_auth().passkey_user_verification(self.get_webauthn_user()))

    @staticmethod
    def user_verification_required(user):
        # The options only ask the browser; this makes the server insist on the
        # UV flag too when the hook says 'required'.
        from modal_2fa.utils import get_custom_auth
        return get_custom_auth().passkey_user_verification(user) == 'required'

    def passkeys_allowed(self):
        return user_may_use_passkeys(self.get_webauthn_user())

    def authentication_command(self, authenticators):
        if not_installed:
            return
        authentication_options = generate_authentication_options(
            rp_id=self.rp_id,
            user_verification=self.user_verification(),
            allow_credentials=[credential_descriptor(credentials) for credentials in authenticators]
        )
        self.save_challenge(authentication_options.challenge, 'auth_challenge')
        return ajax_command('authenticate', authentication=options_to_json(authentication_options))

    def registration_command(self, user):
        from modal_2fa.utils import get_custom_auth
        public_credential_creation_options = generate_registration_options(
            rp_id=self.rp_id,
            user_id=str(user.pk).rjust(16, '0').encode('ascii'),
            user_name=user.username,
            rp_name=self.rp_name,
            # resident_key defaults to 'discouraged': Windows treats anything
            # stronger as a demand for a discoverable credential, which forces
            # PIN setup on hardware security keys (a PIN-less YubiKey becomes
            # unregisterable). Platform authenticators (Windows Hello, Face ID,
            # Android) create synced discoverable passkeys regardless, so the
            # passwordless-later door stays open for them; projects that want
            # discoverable hardware-key credentials too can raise it via the
            # passkey_resident_key hook.
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement(get_custom_auth().passkey_resident_key(user)),
                user_verification=UserVerificationRequirement(get_custom_auth().passkey_user_verification(user)),
            ),
            exclude_credentials=[credential_descriptor(c) for c in get_user_authenticators(user)],
        )
        self.save_challenge(public_credential_creation_options.challenge, 'reg_challenge')
        return ajax_command('register_authentication', creation=options_to_json(public_credential_creation_options))

    def default_credential_name(self, user, response):
        base = 'This device' if response.get('authenticatorAttachment') == 'platform' else 'Security key'
        names = set(get_user_authenticators(user).values_list('name', flat=True))
        name, count = base, 1
        while name in names:
            count += 1
            name = f'{base} {count}'
        return name

    def register_credential(self, user):
        try:
            response = json.loads(self.request.POST['data'])
            authentication_verification = verify_registration_response(
                credential=self.request.POST['data'],
                expected_challenge=self.get_challenge('reg_challenge'),
                expected_origin=self.get_origin(),
                expected_rp_id=self.rp_id,
                require_user_verification=self.user_verification_required(user),
            )
            credential = WebauthnCredential.objects.create(
                user=user,
                rp_id=self.rp_id,
                credential_public_key=bytes_to_base64url(authentication_verification.credential_public_key),
                credential_id=bytes_to_base64url(authentication_verification.credential_id),
                sign_count=authentication_verification.sign_count,
                name=(self.request.POST.get('name', '').strip()[:60]
                      or self.default_credential_name(user, response)),
                transports=credential_transports(response),
            )
        except (InvalidRegistrationResponse, InvalidJSONStructure, KeyError, ValueError) as error:
            self.last_error = error
            return None
        self.request.session.pop('reg_challenge', None)
        return credential

    def get_origin(self):
        if not self.request.is_secure() and self.request.get_host().startswith('localhost'):
            return 'http://' + self.request.get_host()
        return 'https://' + self.request.get_host()

    def save_challenge(self, challenge, key):
        self.request.session[key] = challenge.hex()

    def get_challenge(self, key):
        return bytearray.fromhex(self.request.session[key])

    def get_webauthn_user(self):
        # Views with a part-login user (Modal2FA) set self.user; everywhere else
        # credentials belong to the signed-in user.
        return getattr(self, 'user', None) or self.request.user

    def check_authentication(self, user):

        try:
            response = json.loads(self.request.POST.get('data'))
            credentials = WebauthnCredential.objects.filter(user=user, credential_id=response['id'],
                                                            rp_id=self.rp_id).first()
            if credentials is None:
                # No registered credential matches the asserted id for this user/rp:
                # fail as a clean auth error rather than an AttributeError below.
                self.last_error = 'Unknown credential'
                return False
            authentication_verification = verify_authentication_response(
                credential=response,
                expected_challenge=self.get_challenge('auth_challenge'),
                expected_origin=self.get_origin(),
                expected_rp_id=self.rp_id,
                credential_public_key=base64url_to_bytes(credentials.credential_public_key),
                # Feed the stored counter back in so a cloned/rolled-back authenticator
                # (one reporting a counter <= the last seen value) is rejected. When an
                # authenticator doesn't support counters both sides stay 0 and the check
                # is skipped, as before.
                credential_current_sign_count=credentials.sign_count,
                require_user_verification=self.user_verification_required(user),
            )
            credentials.sign_count = authentication_verification.new_sign_count
            credentials.last_used_on = timezone.now()
            credentials.save()
        except (InvalidAuthenticationResponse, InvalidJSONStructure, KeyError, ValueError, TypeError) as error:
            # KeyError covers a missing auth_challenge: it's popped on success, so
            # a double-submitted or replayed assertion lands here, not in a 500.
            # ValueError/TypeError cover a missing or malformed 'data' body.
            self.last_error = error
            return False
        self.request.session.pop('auth_challenge', None)
        return True

    @ajax_method
    def error(self, data, **_kwargs):
        return self.error_message(f'Passkey error<br>{data}')

    @ajax_method
    def cancelled(self, **_kwargs):
        # The user dismissed the browser/OS passkey dialog: not an error and
        # not a failed second-factor attempt -- leave the modal as it is.
        return self.command_response()

    @ajax_method
    def register(self, **_kwargs):
        if not self.register_credential(self.get_webauthn_user()):
            return self.error_message(f'Could not register passkey<br>{self.last_error}')
        return self.command_response('close')
