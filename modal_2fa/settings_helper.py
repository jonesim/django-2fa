modal_2fa_apps = [
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_hotp',
    'django_otp.plugins.otp_static',
    'modal_2fa',
]

modal_2fa_apps_admin = ['modal_2fa.admin_apps.AdminConfig2fa'] + modal_2fa_apps
