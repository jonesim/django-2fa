from django.contrib.auth.views import LogoutView
from django.urls import path, include
from . import auth


'''
modals = [
    path('login/', auth.ModalLoginView.as_view(), name='login_modal'),
    path('reset-password-confirm/', auth.ResetPasswordModal.as_view(), name='reset_password_modal'),
    path('reset-password/<uidb64>/<token>/', auth.ModalPasswordResetView.as_view(), name='password_reset_confirm'),
    path('change-password/', auth.ModalPasswordChangeView.as_view(), name='change_password'),
    path('2FA/', auth.Modal2FA.as_view(), name='auth_2fa'),
    path('remove-2FA/', auth.Modal2FARemove.as_view(), name='remove_2fa'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('confirm_remember/', auth.ConfirmCookieModal.as_view(), name='confirm_remember'),
    path('user-devices/', auth.UserDevices.as_view(), name='user_devices'),
    path('change-2fa/', auth.Change2FA.as_view(), name='change_2fa'),
]
'''

pattern_dict = {
    'login_modal': ('login/', auth.ModalLoginView),
    'reset_password_modal': ('reset-password-confirm/', auth.ResetPasswordModal),
    'password_reset_confirm': ('reset-password/<uidb64>/<token>/', auth.ModalPasswordResetView),
    'change_password': ('change-password/', auth.ModalPasswordChangeView),
    'auth_2fa': ('2FA/', auth.Modal2FA),
    'remove_2fa': ('remove-2FA/', auth.Modal2FARemove),
    'logout': ('logout/', LogoutView),
    'confirm_remember': ('confirm_remember/', auth.ConfirmCookieModal),
    'user_devices': ('user-devices/', auth.UserDevices),
    'change_2fa': ('change-2fa/', auth.Change2FA)
}


def make_url_patterns(pat_dict):
    return [path(v[0], v[1].as_view(), name=k) for k, v in pat_dict.items()]


urlpatterns = [
    path('user/', include(make_url_patterns(pattern_dict))),
]
