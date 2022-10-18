[![PyPI version](https://badge.fury.io/py/django-modal-2fa.svg)](https://badge.fury.io/py/django-modal-2fa)

## Installation

### settings

    from modal_2fa.settings_helper import modal_2fa_apps_admin
    INSTALLED_APPS += [
        *modal_2fa_apps_admin,
    ]
    
    OTP_TOTP_ISSUER = '**appname**'
    AUTHENTICATION_BACKENDS = ['modal_2fa.auth.CookieBackend']        
    LOGIN_URL ='/auth/login/'
    LOGOUT_REDIRECT_URL = '/auth/login'



**remove** 
    ``'django.contrib.auth'``
from INSTALLED_APPS

### urls

    from modal_2fa.utils import get_custom_auth
    
    urlpatterns += [
        path('', include(get_custom_auth().paths(include_admin=True))),    
    ]
