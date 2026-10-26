from ajax_helpers.utils import ajax_command
from django.urls import reverse, NoReverseMatch
from django_menus.menu import MenuItem, DividerItem
from django_otp import user_has_device

from .utils import get_custom_auth
from .webauthn import user_has_passkey


def user_display(user):
    result = ' '.join([n for n in [user.first_name, user.last_name] if n])
    return result if result else user.username


def add_auth_menu(view):

    if view.request.user.is_authenticated:
        dropdown = [
            MenuItem('', menu_display=f'<b style="color:#495057">{user_display(view.request.user)}</b>', disabled=True),
            DividerItem()
        ]
        # Gate on what the user actually has rather than how this session was
        # established -- a passkey-only user must still reach the management
        # entries (there is no TOTP step in their history to set a marker).
        has_totp = user_has_device(view.request.user)
        if has_totp or user_has_passkey(view.request.user):
            dropdown += [('auth:user_devices', 'Passkeys & trusted devices')]
            if get_custom_auth().allow_totp(view.request.user):
                dropdown += [('auth:change_2fa', 'Change authenticator app' if has_totp
                              else 'Set up authenticator app')]
            dropdown += [('auth:remove_2fa', 'Remove 2FA')]
        else:
            dropdown += [('auth:auth_2fa', 'Set up 2FA')]

        dropdown += [
            ('auth:change_password', 'Change password'),
            DividerItem()
        ]

        if get_custom_auth().can_manage_users(view.request.user, view.request):
            try:
                user_admin = reverse('auth:user_admin_modal')
                dropdown += [
                    MenuItem(user_admin, link_type=MenuItem.HREF, menu_display='User Admin',
                             font_awesome='fas fa-users-cog'),
                    DividerItem()
                ]
            except NoReverseMatch:
                pass

        if get_custom_auth().can_manage_security(view.request.user, view.request):
            try:
                security_admin = reverse('auth:security_admin_modal')
                dropdown += [
                    MenuItem(security_admin, link_type=MenuItem.HREF, menu_display='Security Admin',
                             font_awesome='fas fa-shield-alt'),
                    DividerItem()
                ]
            except NoReverseMatch:
                pass

        dropdown += [
            MenuItem(ajax_command('ajax_post', url=reverse('auth:logout_user')), 'Logout',
                     link_type=MenuItem.AJAX_COMMAND, font_awesome='fas fa-sign-out-alt'),
        ]
        view.add_menu('user_menu', alignment='right').add_items(
            MenuItem(font_awesome='fas fa-user', menu_display='', dropdown=dropdown, placement='bottom-end'),
        )
    else:
        view.add_menu('user_menu', 'button_group', alignment='right').add_items(
            MenuItem('auth:login', menu_display='Sign In', css_classes='btn-primary'),
        )
