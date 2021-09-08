from django.urls import reverse, NoReverseMatch
from django_menus.menu import MenuItem, DividerItem


def user_display(user):
    result = ' '.join([n for n in [user.first_name, user.last_name] if n])
    return result if result else user.username


def add_auth_menu(view):

    if view.request.user.is_authenticated:
        dropdown = [
            MenuItem('', menu_display=f'<b style="color:#495057">{user_display(view.request.user)}</b>', disabled=True),
            DividerItem()
        ]
        if view.request.session.get('authentication_method') in ['2fa', 'cookie']:
            dropdown += [('auth:remove_2fa', 'Remove 2FA'), ('auth:change_2fa', 'Change 2FA'),
                         ('auth:user_devices', 'Authorised devices')]
        else:
            dropdown += [('auth:auth_2fa', 'Add 2FA')]

        dropdown += [
            ('auth:change_password', 'Change password'),
            DividerItem()
        ]

        if view.request.user.has_perm('auth.change_user'):
            try:
                user_admin = reverse('auth:user_admin_modal')
                dropdown += [
                    MenuItem(user_admin, link_type=MenuItem.HREF, menu_display='User Admin',
                             font_awesome='fas fa-users-cog'),
                    DividerItem()
                ]
            except NoReverseMatch:
                pass

        dropdown += [
            MenuItem('auth:logout', font_awesome='fas fa-sign-out-alt'),
        ]
        view.add_menu('user_menu', alignment='right').add_items(
            MenuItem(font_awesome='fas fa-user', menu_display='', dropdown=dropdown, placement='bottom-end'),
        )
    else:
        view.add_menu('user_menu', 'button_group', alignment='right').add_items(
            MenuItem('auth:login', menu_display='Sign In', css_classes='btn-primary'),
        )
