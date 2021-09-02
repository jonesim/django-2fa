from django.conf import settings
from django.utils.module_loading import import_string


def get_client_ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_custom_auth():
    return import_string(getattr(settings, 'AUTHENTICATION_CUSTOMISATION', 'modal_2fa.customise.CustomiseAuth'))
