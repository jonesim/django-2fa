from django.contrib.auth.views import LogoutView
from django.urls import path, include
from . import auth


modals = [
    path('loginmodal/', auth.ModalLoginView.as_view(), name='login_modal'),
    path('resetpassword/<slug:slug>/', auth.ResetPasswordModal.as_view(), name='reset_password_modal'),
    path('login2/<uidb64>/<token>/', auth.ModalPasswordResetView.as_view(), name='password_reset_confirm'),
    path('changepassword/', auth.ModalPasswordChangeView.as_view(), name='change_password'),
    path('2FA/<slug:slug>/', auth.Modal2FA.as_view(), name='auth_2fa'),
    path('2FA/', auth.Modal2FA.as_view(), name='auth_2fa'),
    path('remove_2FA/<slug:slug>/', auth.Modal2FARemove.as_view(), name='remove_2fa'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('confirm_remember/<slug:slug>/', auth.ConfirmCookieModal.as_view(), name='confirm_remember'),
    path('user_devices/', auth.UserDevices.as_view(), name='user_devices'),

]

urlpatterns = [
    path('modals/', include(modals)),
]
