from django_menus.menu import MenuItem, DividerItem
from django.conf import settings
from django.utils.module_loading import import_string


def get_client_ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def add_auth_menu(view):

    if view.request.user.is_authenticated:
        if view.request.session.get('authentication_method') in ['2fa', 'cookie']:
            dropdown = [('remove_2fa', 'Remove 2FA'), ('change_2fa', 'Change 2FA'),
                        ('user_devices', 'Authorised devices')]
        else:
            dropdown = [('auth_2fa', 'Add 2FA')]

        dropdown += [('change_password', 'Change password'), DividerItem(), 'logout']
        view.add_menu('user_menu').add_items(
            MenuItem(menu_display=view.request.user, dropdown=dropdown, placement='bottom-end'),
        )
    else:
        view.add_menu('user_menu', 'button_group').add_items(
            MenuItem('login_modal', menu_display='Sign In', css_classes='btn-primary'),
        )


def get_custom_auth():
    return import_string(getattr(settings, 'AUTHENTICATION_CUSTOMISATION', 'modal_2fa.customise.CustomiseAuth'))
