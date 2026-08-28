import datetime
import json
from time import time
from unittest import mock
from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, get_user_model
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import resolve_url
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.http import urlencode

from django.http import HttpResponse

from django_modals.modals import ModalException
from django_modals.processes import PROCESS_EDIT

from modal_2fa.backends import CookieBackend
from modal_2fa.customise import CustomiseAuth
from modal_2fa.models import FailedLoginAttempt, RememberDeviceCookie, WebauthnCredential
from modal_2fa.users import ModalUserForm
from modal_2fa.utils import get_client_ip_address, get_cookie_backend_path, safe_redirect_url
from modal_2fa.wagtail_auth import Wagtail2FAMiddleware
from modal_2fa.webauthn import WebAuthnMixin

# Placeholder issuer; the guest-detection tests only compare idp against iss,
# so the tenant id here is a dummy and intentionally not a real tenant.
ISS = 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'

test_user = {'username': 'test@test.com',
             'password': 'secret'}

invalid_user = {'username': 'test@test.com',
                'password': 'bad_password'}


class ExcludedIPCustomise(CustomiseAuth):
    # CIDR covering the test client's 127.0.0.1 -- referenced by override_settings
    # as 'examples.tests.ExcludedIPCustomise'.
    excluded_ips = ['127.0.0.0/8']


class TwoFactorOffCustomise(CustomiseAuth):
    # 2FA is out of scope for every request -- referenced by override_settings as
    # 'examples.tests.TwoFactorOffCustomise'. Stands in for a project that mounts the
    # auth views over only part of a site (one host, or one schema) while
    # authenticating users elsewhere through the same AUTHENTICATION_BACKENDS.
    @staticmethod
    def two_factor_enabled(request):
        return False


class SubclassedCookieBackend(CookieBackend):
    # A project scoping the backend to its own needs registers its own dotted path --
    # referenced by override_settings as 'examples.tests.SubclassedCookieBackend'.
    pass


class SsoOnlyCustomise(CustomiseAuth):
    # Every user is Entra-only -- referenced by override_settings as
    # 'examples.tests.SsoOnlyCustomise'.
    @staticmethod
    def password_login_allowed(user):
        return False


class GroupAdminCustomise(CustomiseAuth):
    """Superuser-by-group semantics: is_superuser is ignored entirely.

    Stands in for a project whose membership lives outside the built-in
    permission system -- referenced by override_settings as
    'examples.tests.GroupAdminCustomise'.
    """

    @staticmethod
    def _in_admin_group(user, request=None):
        return request is not None and user.groups.filter(name='user-admins').exists()

    can_manage_users = can_manage_security = _in_admin_group


class WagtailCustomise(CustomiseAuth):
    # A project whose Wagtail admin is mounted at cms/ -- referenced by
    # override_settings as 'examples.tests.WagtailCustomise' and imported by
    # examples.wagtail_test_urls.
    wagtail_admin_prefix = 'cms/'


wagtail_middleware = settings.MIDDLEWARE + ['modal_2fa.wagtail_auth.Wagtail2FAMiddleware']


class UserMixin:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.login_url = resolve_url(settings.LOGIN_URL)
        cls.User = get_user_model()

    def create_user(self, username=test_user['username'], password=test_user['password'], **kwargs):
        user = self.User.objects.create_user(username=username, email=username, password=password, **kwargs)
        return user

    def grant_user_admin(self, user):
        """Give ``user`` the change permission on the project's user model.

        Returns a re-fetched instance -- permission lookups are cached per
        instance, so the original would still report the old answer.
        """
        model = get_user_model()
        user.user_permissions.add(Permission.objects.get(
            content_type__app_label=model._meta.app_label,
            codename=f'change_{model._meta.model_name}'))
        return model.objects.get(pk=user.pk)

    def create_TOTP_user(self):
        user = self.create_user()
        user.totpdevice_set.create(
            key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4', step=30,
            t0=int(time() - (30 * 3)), digits=6, tolerance=0, drift=0
        )
        return user


class LoginTest(UserMixin, TestCase):

    def test_not_logged_in(self):
        response = self.client.get(reverse('protected'))
        assert response.status_code == 302
        assert response.url == reverse('auth:login')[1:] + '?next=/Protected/'

    def checked_logged_in(self):
        response = self.client.get(reverse('protected'))
        assert response.status_code == 200

    def test_login(self):
        self.create_user()
        self.test_not_logged_in()
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.status_code == 200
        self.checked_logged_in()

    def test_login_rejects_unsafe_next(self):
        # An off-site `next` must never drive the post-login redirect.
        self.create_user()
        response = self.client.post(reverse('auth:login') + '?next=https://evil.com/', test_user)
        assert response.status_code == 200
        for command in response.json():
            assert 'evil.com' not in command.get('url', '')
        self.checked_logged_in()

    def test_login_allows_safe_next(self):
        # A local `next` is honoured as before.
        self.create_user()
        response = self.client.post(reverse('auth:login') + '?next=/Protected/', test_user)
        assert response.status_code == 200
        assert {'function': 'redirect', 'url': '/Protected/'} in response.json()

    def test_2fa_cancel_without_part_login(self):
        # An already-authenticated user can reach the 2FA modal with no part_login;
        # cancelling must not 500 on a missing session key.
        user = self.create_user()
        self.client.force_login(user)
        response = self.client.post(reverse('auth:auth_2fa'),
                                    data=json.dumps({'button': 'cancel'}),
                                    content_type='application/json',
                                    HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        assert response.status_code == 200
        # Confirm button_cancel actually ran (not a fallthrough): it re-opens login
        # and logs the user out.
        assert {'function': 'show_modal', 'modal': reverse('auth:login')} in response.json()
        assert '_auth_user_id' not in self.client.session

    def test_TOPT_login(self):
        self.create_TOTP_user()
        self.test_not_logged_in()
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.status_code == 200
        assert response.json() == [{'function': 'close'}, {'function': 'show_modal', 'modal': reverse('auth:auth_2fa')}]
        self.test_not_logged_in()
        response = self.client.post(reverse('auth:auth_2fa'), {'code': '154567'})
        assert response.status_code == 200
        assert self.client.session['authentication_method'] == '2fa'
        self.checked_logged_in()

    def test_username_block(self):
        user = self.create_user()
        self.test_not_logged_in()
        for i in range(1, 12):
            response = self.client.post(reverse('auth:login'), invalid_user)
            failed_attempt = FailedLoginAttempt.objects.get(id=user.id)
            assert failed_attempt.failed_attempts == i
            assert 'id_password' in response.json()[0]['html']
            assert response.status_code == 200
        self.test_not_logged_in()
        response = self.client.post(reverse('auth:login'), invalid_user)
        assert 'id_password' not in response.json()[0]['html']

    def test_username_lockout_expires(self):
        user = self.create_user()
        # Exceed the per-user threshold (default 10) so a timed lockout is applied.
        for _ in range(11):
            self.client.post(reverse('auth:login'), invalid_user)
        locked = FailedLoginAttempt.objects.get(user=user)
        assert locked.locked_time is not None
        # While the window is in effect the login form is replaced by the alert.
        response = self.client.post(reverse('auth:login'), invalid_user)
        assert 'id_password' not in response.json()[0]['html']
        # Simulate the lockout window elapsing.
        locked.locked_time = datetime.datetime.now() - datetime.timedelta(seconds=1)
        locked.save()
        response = self.client.post(reverse('auth:login'), invalid_user)
        # The form is back, and the expired lock has been cleared.
        assert 'id_password' in response.json()[0]['html']
        refreshed = FailedLoginAttempt.objects.get(user=user)
        assert refreshed.locked_time is None


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.ExcludedIPCustomise')
class ExcludedIPTest(UserMixin, TestCase):
    """Allowlisted IPs bypass the shared-IP lockout but not the per-user one."""

    nonexistent = {'username': 'ghost@nowhere.com', 'password': 'whatever'}

    def test_excluded_ip_not_locked(self):
        # Spray well past the IP threshold (default 20) with an unknown username,
        # so only the IP path could trigger.
        for _ in range(25):
            self.client.post(reverse('auth:login'), self.nonexistent)
        # No shared-IP row is ever recorded for an allowlisted address.
        assert not FailedLoginAttempt.objects.filter(user__isnull=True).exists()
        # And login is still served (not replaced by the 'IP Blocked' alert).
        response = self.client.post(reverse('auth:login'), self.nonexistent)
        assert 'id_password' in response.json()[0]['html']

    def test_excluded_ip_user_lockout_still_applies(self):
        user = self.create_user()
        # Wrong password for a real user, past the per-user threshold (default 10).
        for _ in range(11):
            self.client.post(reverse('auth:login'), invalid_user)
        # The account still locks -- per-user protection is unaffected by the
        # IP allowlist...
        assert FailedLoginAttempt.objects.get(user=user).locked_time is not None
        # ...while the shared IP is never recorded.
        assert not FailedLoginAttempt.objects.filter(user__isnull=True).exists()


class IpExcludedHelperTest(TestCase):
    """Unit coverage for CustomiseAuth.is_ip_excluded (CIDR + robustness)."""

    def test_cidr_and_exact_match(self):
        class C(CustomiseAuth):
            excluded_ips = ['10.0.0.0/24', '203.0.113.5']
        assert C.is_ip_excluded('10.0.0.7') is True      # inside CIDR
        assert C.is_ip_excluded('203.0.113.5') is True   # exact host
        assert C.is_ip_excluded('10.0.1.7') is False     # outside CIDR

    def test_empty_default(self):
        assert CustomiseAuth.is_ip_excluded('127.0.0.1') is False

    def test_malformed_inputs_are_safe(self):
        class C(CustomiseAuth):
            excluded_ips = ['not-an-ip', '10.0.0.0/24']
        assert C.is_ip_excluded(None) is False
        assert C.is_ip_excluded('garbage') is False
        # The malformed entry is skipped; the valid one still matches.
        assert C.is_ip_excluded('10.0.0.5') is True


class TwoFactorThrottleTest(UserMixin, TestCase):
    """The 2FA step is rate-limited just like the password step, so a stolen
    password can't buy unlimited TOTP guesses."""

    valid_code = '154567'   # valid for the fixed device key/time in create_TOTP_user
    wrong_code = '000000'

    def _start_2fa(self):
        # Correct password for a TOTP user advances to the 2FA modal (part_login).
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.json() == [{'function': 'close'},
                                   {'function': 'show_modal', 'modal': reverse('auth:auth_2fa')}]

    def test_wrong_code_accumulates_and_locks(self):
        user = self.create_TOTP_user()
        self._start_2fa()
        # Each wrong code is recorded against the user (default threshold 10).
        for i in range(1, 12):
            response = self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
            assert FailedLoginAttempt.objects.get(user=user).failed_attempts == i
            assert 'id_code' in response.json()[0]['html']
        # Threshold exceeded: the lock is applied and the code field is withdrawn.
        assert FailedLoginAttempt.objects.get(user=user).locked_time is not None
        response = self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
        assert 'id_code' not in response.json()[0]['html']

    def test_locked_rejects_correct_code(self):
        self.create_TOTP_user()
        self._start_2fa()
        for _ in range(11):
            self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
        # Even the correct code must not log in while the lockout window is active.
        self.client.post(reverse('auth:auth_2fa'), {'code': self.valid_code})
        assert '_auth_user_id' not in self.client.session
        assert 'authentication_method' not in self.client.session

    def test_locked_attempt_does_not_extend_lockout(self):
        user = self.create_TOTP_user()
        self._start_2fa()
        for _ in range(11):
            self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
        attempts = FailedLoginAttempt.objects.get(user=user).failed_attempts
        # Retrying while locked must not keep incrementing the counter.
        self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
        assert FailedLoginAttempt.objects.get(user=user).failed_attempts == attempts

    def test_success_clears_attempts(self):
        user = self.create_TOTP_user()
        self._start_2fa()
        # Prior failures recorded against this user (set directly to avoid the
        # per-device django-otp throttle that would block an immediate retry).
        FailedLoginAttempt.objects.create(user=user, failed_attempts=3)
        response = self.client.post(reverse('auth:auth_2fa'), {'code': self.valid_code})
        assert self.client.session['authentication_method'] == '2fa'
        assert not FailedLoginAttempt.objects.filter(user=user).exists()

    def test_ip_lock_does_not_block_2fa(self):
        # A shared-IP lockout (caused by an unrelated attacker spraying logins)
        # must not block a legitimate user who has already reached the 2FA step:
        # the 2FA throttle is user-scoped, not IP-scoped.
        self.create_TOTP_user()
        self._start_2fa()   # part_login established while the IP is still clean
        FailedLoginAttempt.objects.create(
            ip_address='127.0.0.1', failed_attempts=99,
            locked_time=datetime.datetime.now() + datetime.timedelta(seconds=30),
        )
        # The user's own 2FA is unaffected -- the code field is still presented
        # (an IP block would have replaced it with the lockout alert).
        response = self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
        assert 'id_code' in response.json()[0]['html']

    def test_wrong_code_does_not_touch_ip_counter(self):
        # Wrong 2FA codes are recorded against the user only, never the shared IP.
        self.create_TOTP_user()
        self._start_2fa()
        self.client.post(reverse('auth:auth_2fa'), {'code': self.wrong_code})
        assert not FailedLoginAttempt.objects.filter(user__isnull=True).exists()

    def test_password_failures_carry_into_2fa(self):
        user = self.create_TOTP_user()
        # Two bad passwords build up a counter.
        for _ in range(2):
            self.client.post(reverse('auth:login'), invalid_user)
        assert FailedLoginAttempt.objects.get(user=user).failed_attempts == 2
        # Reaching 2FA with the correct password must NOT reset that counter,
        # otherwise the 2FA throttle would start fresh on every login.
        self._start_2fa()
        assert FailedLoginAttempt.objects.get(user=user).failed_attempts == 2


class MicrosoftGuestTest(TestCase):
    """Guest detection / admission policy on CustomiseAuth (no DB or HTTP needed)."""

    def test_member_by_acct_allowed(self):
        claims = {'iss': ISS, 'acct': 0}
        assert CustomiseAuth.microsoft_is_guest(claims) is False
        assert CustomiseAuth.microsoft_allowed(claims) is True

    def test_guest_by_acct_blocked(self):
        claims = {'iss': ISS, 'acct': 1}
        assert CustomiseAuth.microsoft_is_guest(claims) is True
        assert CustomiseAuth.microsoft_allowed(claims) is False

    def test_guest_by_idp_mismatch_without_acct(self):
        # No acct claim configured, but the home idp differs from the issuer.
        claims = {'iss': ISS, 'idp': 'https://sts.windows.net/other-tenant/'}
        assert CustomiseAuth.microsoft_is_guest(claims) is True
        assert CustomiseAuth.microsoft_allowed(claims) is False

    def test_member_without_acct_or_idp(self):
        # Native member: no acct, no idp emitted.
        claims = {'iss': ISS}
        assert CustomiseAuth.microsoft_is_guest(claims) is False
        assert CustomiseAuth.microsoft_allowed(claims) is True

    def test_idp_equal_to_iss_is_member(self):
        claims = {'iss': ISS, 'idp': ISS}
        assert CustomiseAuth.microsoft_is_guest(claims) is False

    def test_allow_guests_admits_guest(self):
        class AllowGuests(CustomiseAuth):
            microsoft_allow_guests = True

        claims = {'iss': ISS, 'acct': 1}
        assert AllowGuests.microsoft_is_guest(claims) is True
        assert AllowGuests.microsoft_allowed(claims) is True


class SafeRedirectTest(TestCase):
    """safe_redirect_url accepts only local targets (no DB or HTTP needed)."""

    def setUp(self):
        self.request = RequestFactory().get('/auth/login/')

    def test_relative_path_allowed(self):
        assert safe_redirect_url(self.request, '/Protected/') == '/Protected/'

    def test_absolute_external_blocked(self):
        assert safe_redirect_url(self.request, 'https://evil.com/') is None

    def test_scheme_relative_blocked(self):
        assert safe_redirect_url(self.request, '//evil.com') is None

    def test_javascript_blocked(self):
        assert safe_redirect_url(self.request, 'javascript:alert(1)') is None

    def test_unsafe_returns_fallback(self):
        assert safe_redirect_url(self.request, 'https://evil.com/', fallback='/') == '/'

    def test_missing_returns_fallback(self):
        assert safe_redirect_url(self.request, None, fallback='/') == '/'


class WebAuthnSignCountTest(UserMixin, TestCase):
    """The stored counter is forwarded so clone/rollback detection is active."""

    def _harness(self, request):
        # Build the mixin without its settings-driven __init__; we only exercise
        # check_authentication, which needs request/rp_id/last_error.
        harness = WebAuthnMixin.__new__(WebAuthnMixin)
        harness.last_error = None
        harness.rp_id = 'localhost'
        harness.request = request
        return harness

    def _request(self, credential_id):
        request = RequestFactory().post('/auth/2FA/', {'data': json.dumps({'id': credential_id})})
        request.session = {'auth_challenge': '00'}
        return request

    def test_stored_sign_count_is_verified(self):
        user = self.create_user()
        WebauthnCredential.objects.create(
            user=user, rp_id='localhost', credential_public_key='AAAA',
            credential_id='abc123', sign_count=5,
        )
        harness = self._harness(self._request('abc123'))
        verified = mock.Mock(new_sign_count=6)
        with mock.patch('modal_2fa.webauthn.verify_authentication_response', return_value=verified) as verify, \
                mock.patch('modal_2fa.webauthn.base64url_to_bytes', return_value=b''):
            assert harness.check_authentication(user) is True
        # The last seen counter (5), not a hardcoded 0, is what gets verified.
        assert verify.call_args.kwargs['credential_current_sign_count'] == 5
        # And the new counter is persisted for next time.
        assert WebauthnCredential.objects.get(credential_id='abc123').sign_count == 6

    def test_unknown_credential_fails_cleanly(self):
        user = self.create_user()
        # An asserted id with no matching credential must fail, not raise.
        harness = self._harness(self._request('does-not-exist'))
        with mock.patch('modal_2fa.webauthn.verify_authentication_response') as verify:
            assert harness.check_authentication(user) is False
        verify.assert_not_called()


class PasswordLoginAllowedHookTest(UserMixin, TestCase):
    """The password_login_allowed policy hook (default + the demo's group rule)."""

    def test_default_allows_password(self):
        user = self.create_user()
        assert CustomiseAuth.password_login_allowed(user) is True

    def test_example_blocks_sso_only_group(self):
        from django.contrib.auth.models import Group
        from examples.customise import ExampleCustomise
        user = self.create_user()
        # Not in the group -> normal password login.
        assert ExampleCustomise.password_login_allowed(user) is True
        user.groups.add(Group.objects.create(name='sso-only'))
        # In the 'sso-only' group -> Entra-only, password refused.
        assert ExampleCustomise.password_login_allowed(user) is False


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.SsoOnlyCustomise')
class SsoOnlyLoginTest(UserMixin, TestCase):
    """An Entra-only user (password_login_allowed -> False) cannot log in with a
    password. Enforcement is at the backend, so the Microsoft path -- which never
    checks a password -- is unaffected."""

    def test_backend_refuses_correct_password(self):
        self.create_user()
        request = RequestFactory().post(self.login_url)
        # Correct credentials, but policy blocks the password path entirely.
        user = CookieBackend().authenticate(
            request, username=test_user['username'], password=test_user['password'])
        assert user is None

    def test_http_login_blocked(self):
        self.create_user()
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.status_code == 200
        # Correct password, but the user is never authenticated.
        assert '_auth_user_id' not in self.client.session


class TwoFactorEnabledHookTest(UserMixin, TestCase):
    """The two_factor_enabled scope hook: default on, and no request to scope against."""

    def test_default_is_enabled(self):
        assert CustomiseAuth.two_factor_enabled(RequestFactory().post('/')) is True

    def test_no_request_still_answers(self):
        # authenticate() can be called without a request; there is nothing to scope
        # against, so the default applies rather than blowing up.
        assert CustomiseAuth.two_factor_enabled(None) is True

    def test_totp_user_is_held_at_2fa_when_enabled(self):
        # The contrast for the disabled case below: same user, hook left at its default.
        self.create_TOTP_user()
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.status_code == 200
        assert '_auth_user_id' not in self.client.session


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.TwoFactorOffCustomise')
class TwoFactorDisabledTest(UserMixin, TestCase):
    """With two_factor_enabled -> False, CookieBackend is a plain ModelBackend.

    A user who *has* a TOTP device is the interesting case: without the hook the
    backend parks a part_login and returns None, so a login outside the 2FA area
    fails unless ModelBackend is left behind CookieBackend to catch it.
    """

    def request_with_session(self):
        # A real session (rather than a bare RequestFactory request) so that the
        # unhooked behaviour runs to completion and each test below fails on its own
        # assertion rather than on a missing-attribute error part way through.
        request = RequestFactory().post(self.login_url)
        request.session = {}
        return request

    def authenticate(self, request, user=test_user):
        return CookieBackend().authenticate(
            request, username=user['username'], password=user['password'])

    def test_backend_returns_a_totp_user_directly(self):
        self.create_TOTP_user()
        user = self.authenticate(self.request_with_session())
        assert user is not None
        assert user.get_username() == test_user['username']

    def test_no_part_login_is_parked(self):
        # A parked part_login would be left behind for auth views that are not routed
        # into this area to consume.
        self.create_TOTP_user()
        request = self.request_with_session()
        self.authenticate(request)
        assert CookieBackend.part_login_key not in request.session

    def test_no_authentication_method_is_recorded(self):
        # Nothing here cleared the second factor, so nothing should claim it did.
        self.create_TOTP_user()
        request = self.request_with_session()
        self.authenticate(request)
        assert 'authentication_method' not in request.session

    def test_trusted_device_table_is_not_read(self):
        # The point for a multi-tenant project: a request from outside the 2FA area
        # must not touch modal_2fa's tables at all.
        self.create_TOTP_user()
        with mock.patch.object(RememberDeviceCookie, 'test_cookie', return_value=False) as test_cookie:
            self.authenticate(self.request_with_session())
        test_cookie.assert_not_called()

    def test_http_login_completes_without_a_2fa_step(self):
        self.create_TOTP_user()
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.status_code == 200
        assert '_auth_user_id' in self.client.session

    def test_wrong_password_is_still_refused(self):
        # Scoping 2FA out must not scope out authentication.
        self.create_TOTP_user()
        assert self.authenticate(self.request_with_session(), invalid_user) is None


class ModalTitleTest(UserMixin, TestCase):
    """Every auth modal should render a title rather than an empty header."""

    def test_remove_2fa_modal_has_a_title(self):
        from modal_2fa.auth import Modal2FARemove
        assert Modal2FARemove.modal_title == 'Remove 2FA'

    def test_remove_2fa_modal_renders_its_title(self):
        user = self.create_TOTP_user()
        self.client.force_login(user)
        response = self.client.get(reverse('auth:remove_2fa'))
        assert response.status_code == 200
        assert 'Remove 2FA' in response.content.decode()


class CookieBackendPathTest(TestCase):
    """The dotted path recorded on the session when we complete a login ourselves."""

    def test_default_single_backend(self):
        with override_settings(AUTHENTICATION_BACKENDS=['modal_2fa.auth.CookieBackend']):
            assert get_cookie_backend_path() == 'modal_2fa.auth.CookieBackend'

    def test_subclass_path_is_used(self):
        with override_settings(AUTHENTICATION_BACKENDS=['examples.tests.SubclassedCookieBackend']):
            assert get_cookie_backend_path() == 'examples.tests.SubclassedCookieBackend'

    def test_cookie_backend_found_behind_another_backend(self):
        # Not simply the first entry: the CookieBackend one is what matters.
        with override_settings(AUTHENTICATION_BACKENDS=[
                'django.contrib.auth.backends.ModelBackend',
                'examples.tests.SubclassedCookieBackend']):
            assert get_cookie_backend_path() == 'examples.tests.SubclassedCookieBackend'

    def test_falls_back_when_no_cookie_backend_registered(self):
        with override_settings(AUTHENTICATION_BACKENDS=['django.contrib.auth.backends.ModelBackend']):
            assert get_cookie_backend_path() == 'modal_2fa.auth.CookieBackend'

    def test_unimportable_entry_is_skipped(self):
        with override_settings(AUTHENTICATION_BACKENDS=[
                'no.such.module.Backend', 'examples.tests.SubclassedCookieBackend']):
            assert get_cookie_backend_path() == 'examples.tests.SubclassedCookieBackend'


@override_settings(AUTHENTICATION_BACKENDS=['examples.tests.SubclassedCookieBackend'])
class SubclassedBackendLoginTest(UserMixin, TestCase):
    """A project that subclasses CookieBackend must stay logged in after 2FA.

    django.contrib.auth.get_user() only restores a session whose recorded backend
    path is listed in AUTHENTICATION_BACKENDS. Recording our own path when the
    project registered a subclass means the session is discarded on the very next
    request and the user is silently signed out again.
    """

    def test_2fa_login_survives_the_next_request(self):
        self.create_TOTP_user()
        response = self.client.post(reverse('auth:login'), test_user)
        assert response.status_code == 200
        response = self.client.post(reverse('auth:auth_2fa'), {'code': '154567'})
        assert response.status_code == 200
        assert self.client.session['authentication_method'] == '2fa'
        # The session records the registered path, so it is honoured rather than dropped.
        assert self.client.session[BACKEND_SESSION_KEY] == 'examples.tests.SubclassedCookieBackend'
        # And the proof that matters: a protected page, on a fresh request.
        assert self.client.get(reverse('protected')).status_code == 200


class ClientIpTest(TestCase):
    """X-Forwarded-For is only trusted behind a configured reverse proxy."""

    def _request(self, **extra):
        return RequestFactory().get('/', REMOTE_ADDR='10.0.0.1', **extra)

    @override_settings(BEHIND_REVERSE_PROXY=False)
    def test_xff_ignored_without_proxy(self):
        # No proxy: a spoofed header must not override the real peer address.
        request = self._request(HTTP_X_FORWARDED_FOR='1.2.3.4')
        assert get_client_ip_address(request) == '10.0.0.1'

    @override_settings(BEHIND_REVERSE_PROXY=True)
    def test_rightmost_xff_used_behind_proxy(self):
        # Behind a proxy: the right-most (proxy-observed) entry wins; the
        # client-spoofable left-most entry is ignored.
        request = self._request(HTTP_X_FORWARDED_FOR='1.2.3.4, 9.9.9.9')
        assert get_client_ip_address(request) == '9.9.9.9'

    @override_settings(BEHIND_REVERSE_PROXY=True)
    def test_remote_addr_used_when_no_xff(self):
        assert get_client_ip_address(self._request()) == '10.0.0.1'

    @override_settings(AUTHENTICATION_TRUSTED_PROXY_COUNT=1)
    def test_one_proxy_ignores_spoofed_left_entry(self):
        request = self._request(HTTP_X_FORWARDED_FOR='9.9.9.9, 1.2.3.4')
        assert get_client_ip_address(request) == '1.2.3.4'

    @override_settings(AUTHENTICATION_TRUSTED_PROXY_COUNT=2)
    def test_two_proxies_pick_client(self):
        # CDN -> Traefik: client is the 2nd entry from the right.
        request = self._request(HTTP_X_FORWARDED_FOR='1.1.1.1, 2.2.2.2')
        assert get_client_ip_address(request) == '1.1.1.1'

    @override_settings(AUTHENTICATION_TRUSTED_PROXY_COUNT=2)
    def test_two_proxies_spoof_safe(self):
        # A forged entry can only be prepended; xff[-2] stays anchored to the client.
        request = self._request(HTTP_X_FORWARDED_FOR='evil, 1.1.1.1, 2.2.2.2')
        assert get_client_ip_address(request) == '1.1.1.1'

    @override_settings(AUTHENTICATION_TRUSTED_PROXY_COUNT=2)
    def test_short_header_falls_back_to_remote_addr(self):
        # Fewer hops than configured (proxy bypassed/misconfigured): don't trust it.
        request = self._request(HTTP_X_FORWARDED_FOR='1.2.3.4')
        assert get_client_ip_address(request) == '10.0.0.1'

    @override_settings(BEHIND_REVERSE_PROXY=True, AUTHENTICATION_TRUSTED_PROXY_COUNT=2)
    def test_explicit_count_overrides_legacy_flag(self):
        request = self._request(HTTP_X_FORWARDED_FOR='1.1.1.1, 2.2.2.2, 3.3.3.3')
        # count=2 -> xff[-2]; the legacy boolean (which would give xff[-1]) is ignored.
        assert get_client_ip_address(request) == '2.2.2.2'


class AccessHookDefaultsTest(UserMixin, TestCase):
    """The defaults for can_manage_users / can_manage_security preserve the
    behaviour of the hardcoded checks they replaced."""

    def test_permission_string_is_derived_from_the_user_model(self):
        # The point of the hook: the permission tracks AUTH_USER_MODEL instead of
        # naming auth.User, which does not exist once the model is swapped out.
        user = self.create_user()
        model = get_user_model()
        with mock.patch.object(type(user), 'has_perm', return_value=True) as has_perm:
            assert CustomiseAuth.can_manage_users(user) is True
        has_perm.assert_called_once_with(f'{model._meta.app_label}.change_{model._meta.model_name}')

    def test_can_manage_users_follows_the_real_permission(self):
        user = self.create_user()
        assert CustomiseAuth.can_manage_users(user) is False
        assert CustomiseAuth.can_manage_users(self.grant_user_admin(user)) is True

    def test_can_manage_security_defaults_to_is_superuser(self):
        user = self.create_user()
        assert CustomiseAuth.can_manage_security(user) is False
        user.is_superuser = True
        assert CustomiseAuth.can_manage_security(user) is True

    def test_class_level_permission_resolution(self):
        # django-modals resolves permission on the class (not an instance) when a
        # caller asks whether to render an edit button; it passes None as self, so
        # ModalUserForm.permission must cope with having no request.
        user = self.create_user()
        assert ModalUserForm.user_has_perm(ModalUserForm, user, PROCESS_EDIT) is False
        assert ModalUserForm.user_has_perm(ModalUserForm, self.grant_user_admin(user), PROCESS_EDIT) is True


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.GroupAdminCustomise')
class GroupAdminAccessTest(UserMixin, TestCase):
    """A customisation that decides access by group membership alone overrides
    both the permission check and is_superuser."""

    def signed_in(self, in_group, **kwargs):
        user = self.create_user(**kwargs)
        if in_group:
            user.groups.add(Group.objects.get_or_create(name='user-admins')[0])
        self.client.force_login(user)
        return user

    def test_group_member_reaches_both_modals(self):
        self.signed_in(True)
        assert self.client.get(reverse('auth:user_admin_modal')).status_code == 200
        assert self.client.get(reverse('auth:security_admin_modal')).status_code == 200

    def test_superuser_outside_the_group_is_denied(self):
        # is_superuser is deliberately ignored by this customisation.
        self.signed_in(False, is_superuser=True, is_staff=True)
        with self.assertRaises(ModalException):
            self.client.get(reverse('auth:user_admin_modal'))
        with self.assertRaises(ModalException):
            self.client.get(reverse('auth:security_admin_modal'))

    def test_group_member_reaches_user_and_invite_modals(self):
        user = self.signed_in(True)
        assert self.client.get(reverse('auth:user', args=[f'pk-{user.pk}'])).status_code == 200
        assert self.client.get(reverse('auth:invite_user_confirm', args=[f'pk-{user.pk}'])).status_code == 200


class UserTableAccessTest(UserMixin, TestCase):
    """UserTable lists every user and is routed at /user-table/ in the demo, so
    it needs the same gate as the modal that embeds it."""

    url = '/user-table/'

    def get(self):
        # django_datatables' detect_device reads HTTP_USER_AGENT unguarded, so a
        # request that gets past the gate needs one.
        return self.client.get(self.url, HTTP_USER_AGENT='test')

    def test_anonymous_is_sent_to_login(self):
        response = self.get()
        assert response.status_code == 302
        assert response.url.startswith(self.login_url)

    def test_signed_in_without_permission_is_forbidden(self):
        self.client.force_login(self.create_user())
        assert self.get().status_code == 403

    def test_permitted_user_gets_the_table(self):
        self.client.force_login(self.grant_user_admin(self.create_user()))
        assert self.get().status_code == 200


class AuthMenuVisibilityTest(UserMixin, TestCase):
    """add_auth_menu offers the admin entries according to the hooks."""

    def menu_html(self, user):
        self.client.force_login(user)
        return self.client.get(reverse('basic')).content.decode()

    def test_plain_user_sees_neither_entry(self):
        html = self.menu_html(self.create_user())
        assert reverse('auth:user_admin_modal') not in html
        assert reverse('auth:security_admin_modal') not in html

    def test_permission_reveals_user_admin_only(self):
        html = self.menu_html(self.grant_user_admin(self.create_user()))
        assert reverse('auth:user_admin_modal') in html
        assert reverse('auth:security_admin_modal') not in html

    def test_superuser_sees_both(self):
        html = self.menu_html(self.create_user(is_superuser=True, is_staff=True))
        assert reverse('auth:user_admin_modal') in html
        assert reverse('auth:security_admin_modal') in html

    @override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.GroupAdminCustomise')
    def test_group_membership_reveals_both(self):
        user = self.create_user()
        user.groups.add(Group.objects.create(name='user-admins'))
        html = self.menu_html(user)
        assert reverse('auth:user_admin_modal') in html
        assert reverse('auth:security_admin_modal') in html


class RememberCookieFlagsTest(UserMixin, TestCase):
    """The trusted-device (2FA-bypass) cookie carries hardened flags."""

    def test_set_cookie_security_flags(self):
        user = self.create_user()
        cookie = RememberDeviceCookie.objects.create(user=user, key='abc', active=True)
        response = HttpResponse()
        cookie.set_cookie(response)
        morsel = response.cookies[RememberDeviceCookie.cookie_name(user)]
        assert morsel['secure']
        assert morsel['httponly']
        assert morsel['samesite'] == 'Lax'


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.WagtailCustomise',
                   ROOT_URLCONF='examples.wagtail_test_urls',
                   MIDDLEWARE=wagtail_middleware)
class WagtailShadowUrlTest(UserMixin, TestCase):
    """Wagtail's own auth URLs are shadowed by the modal_2fa equivalents.

    The fake Wagtail admin returns 200 from every route, so a 302 here proves the
    modal_2fa pattern won the resolution.
    """

    def test_login_redirects_to_modal_preserving_next(self):
        response = self.client.get('/cms/login/?next=/cms/pages/')
        assert response.status_code == 302
        assert response.url == reverse('auth:login') + '?' + urlencode({'next': '/cms/pages/'})

    def test_login_drops_unsafe_next(self):
        # An off-site next falls back to the Wagtail admin root, never evil.com.
        response = self.client.get('/cms/login/?next=https://evil.com/')
        assert response.url == reverse('auth:login') + '?' + urlencode({'next': '/cms/'})

    def test_logout_accepts_post(self):
        # Wagtail's admin posts to its logout URL, so the shadow mounts LogoutView
        # itself rather than redirecting (a 302 would downgrade the POST to GET).
        self.client.force_login(self.create_user())
        response = self.client.post('/cms/logout/')
        assert response.status_code == 302
        assert '_auth_user_id' not in self.client.session

    def test_password_reset_urls_redirect_to_modal(self):
        for url in ('/cms/password_reset/',
                    '/cms/password_reset/done/',
                    '/cms/password_reset/confirm/MQ/abcd-efgh/'):
            response = self.client.get(url)
            assert response.status_code == 302, url
            assert response.url == reverse('auth:reset_password'), url
        response = self.client.get('/cms/password_reset/complete/')
        assert response.url == reverse('auth:login')


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.WagtailCustomise',
                   ROOT_URLCONF='examples.wagtail_test_urls',
                   MIDDLEWARE=wagtail_middleware)
class Wagtail2FAMiddlewareTest(UserMixin, TestCase):
    """The Wagtail admin is gated on a second factor, as AdminSite2FA gates Django's."""

    def _login(self, method=None):
        self.client.force_login(self.create_user())
        if method:
            session = self.client.session
            session['authentication_method'] = method
            session.save()

    def test_password_only_session_sent_to_2fa(self):
        self._login()
        response = self.client.get('/cms/pages/')
        assert response.status_code == 302
        assert response.url == reverse('auth:auth_2fa') + '?' + urlencode({'next': '/cms/pages/'})

    def test_full_path_including_query_is_preserved(self):
        self._login()
        response = self.client.get('/cms/pages/?ordering=title')
        assert response.url == reverse('auth:auth_2fa') + '?' + urlencode({'next': '/cms/pages/?ordering=title'})

    def test_verified_session_allowed(self):
        for method in ('2fa', 'microsoft'):
            with self.subTest(method=method):
                self._login(method)
                assert self.client.get('/cms/').status_code == 200
                self.client.logout()
                self.User.objects.all().delete()

    def test_cookie_session_is_not_a_second_factor(self):
        # A trusted-device cookie skips the 2FA step, so it must not open the CMS.
        self._login('cookie')
        assert self.client.get('/cms/').status_code == 302

    def test_anonymous_left_to_wagtail(self):
        # Wagtail redirects anonymous users itself (WAGTAILADMIN_LOGIN_URL); the
        # middleware must not intercept and mask that.
        assert self.client.get('/cms/').status_code == 200

    def test_shadowed_auth_urls_not_gated(self):
        # Otherwise an unverified user could never log out or reach the login modal.
        self._login()
        assert self.client.get('/cms/login/').url.startswith(reverse('auth:login'))
        assert self.client.get('/cms/password_reset/').url == reverse('auth:reset_password')

    def test_other_urls_untouched(self):
        self._login()
        assert self.client.get(reverse('protected')).status_code == 200


@override_settings(ROOT_URLCONF='examples.wagtail_off_test_urls', MIDDLEWARE=wagtail_middleware)
class WagtailDisabledTest(UserMixin, TestCase):
    """Without wagtail_admin_prefix nothing is registered and the middleware is inert."""

    def test_urls_not_shadowed(self):
        assert self.client.get('/cms/login/').status_code == 200

    def test_middleware_inert(self):
        self.client.force_login(self.create_user())
        assert self.client.get('/cms/').status_code == 200


@override_settings(AUTHENTICATION_CUSTOMISATION='examples.tests.WagtailCustomise')
class WagtailMisconfigurationTest(TestCase):
    """Misconfigurations that would silently weaken the gate fail loudly instead."""

    @override_settings(ROOT_URLCONF='examples.wagtail_misordered_test_urls')
    def test_wagtail_include_above_shadow_refused_at_startup(self):
        # Wagtail's real (unauthenticated) login wins the resolution, so the
        # middleware would gate the admin around a still-open login. Refuse.
        with self.assertRaisesMessage(ImproperlyConfigured, 'wagtailadmin_login'):
            Wagtail2FAMiddleware(lambda request: HttpResponse())

    @override_settings(ROOT_URLCONF='examples.wagtail_test_urls')
    def test_missing_request_user_refused(self):
        # Installed before AuthenticationMiddleware there is no request.user;
        # failing open here would switch the 2FA gate off silently.
        request = RequestFactory().get('/cms/pages/')
        with self.assertRaisesMessage(ImproperlyConfigured, 'AuthenticationMiddleware'):
            Wagtail2FAMiddleware.check_request(request)
