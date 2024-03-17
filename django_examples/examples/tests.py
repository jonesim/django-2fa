from time import time
from django.conf import settings
from django.contrib.auth import get_user_model
from django.shortcuts import resolve_url
from django.test import TestCase
from django.urls import reverse

from modal_2fa.models import FailedLoginAttempt

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
