import datetime
import json
from time import time
from unittest import mock
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import resolve_url
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from django.http import HttpResponse

from modal_2fa.customise import CustomiseAuth
from modal_2fa.models import FailedLoginAttempt, RememberDeviceCookie, WebauthnCredential
from modal_2fa.utils import get_client_ip_address, safe_redirect_url
from modal_2fa.webauthn import WebAuthnMixin

# Placeholder issuer; the guest-detection tests only compare idp against iss,
# so the tenant id here is a dummy and intentionally not a real tenant.
ISS = 'https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0'

test_user = {'username': 'test@test.com',
             'password': 'secret'}

invalid_user = {'username': 'test@test.com',
                'password': 'bad_password'}


class UserMixin:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.login_url = resolve_url(settings.LOGIN_URL)
        cls.User = get_user_model()

    def create_user(self, username=test_user['username'], password=test_user['password'], **kwargs):
        user = self.User.objects.create_user(username=username, email=username, password=password, **kwargs)
        return user

    def create_TOTP_user(self):
        user = self.create_user()
        user.totpdevice_set.create(
            key='2a2bbba1092ffdd25a328ad1a0a5f5d61d7aacc4', step=30,
            t0=int(time() - (30 * 3)), digits=6, tolerance=0, drift=0
        )


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
