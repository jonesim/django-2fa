from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django_modals.modals import TemplateModal
from django_modals.datatables import EditColumn
from django_datatables.datatables import DatatableView, DatatableTable
from django_datatables.columns import DatatableColumn
from .utils import get_custom_auth

UserModel = get_user_model()


class UserColumn(DatatableColumn):

    def setup_results(self, request, all_results):
        if 'users' not in all_results:
            all_results['users'] = {u.id: u for u in UserModel.objects.all()}
        if 'custom_auth' not in all_results:
            all_results['custom_auth'] = get_custom_auth()


class Cookies(UserColumn):
    customise = get_custom_auth()

    @staticmethod
    def row_result(data, page_data):
        return (data['no_cookies'] if page_data['custom_auth'].allowed_remember(page_data['users'][data['id']])
                else 'Disabled')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.annotations = {'no_cookies': Count('rememberdevicecookie__id',
                                                filter=Q(rememberdevicecookie__active=True))}


class Optional2fa(UserColumn):

    @staticmethod
    def row_result(data, page_data):
        return 'Optional' if page_data['custom_auth'].user_2fa_optional(page_data['users'][data['id']]) else 'Required'


class Password(UserColumn):

    @staticmethod
    def row_result(data, page_data):
        return 'Not set' if not page_data['users'][data['id']].password else None


def add_user_columns(table):
    table.add_columns(
        'id',
        'username',
        DatatableColumn(column_name='TOTP', title='TOTP',
                        annotations={'TOTP': Count('totpdevice__id', filter=Q(totpdevice__confirmed=True))}),
        Cookies(column_name='Cookies'),
        Optional2fa(column_name='2FA', title='2FA'),
        Password(column_name='Password'),
        'last_login',
        EditColumn(modal_name='auth:invite_user_confirm', button_text='Invite'),
        EditColumn(modal_name='auth:user'),
    )


class UserTable(DatatableView):
    template_name = 'modal_2fa/base.html'
    model = UserModel

    @staticmethod
    def setup_table(table):
        add_user_columns(table)


class UserAdminModal(TemplateModal):
    modal_template = 'modal_2fa/user_admin_modal.html'

    def modal_context(self):
        self.size = 'xl'
        table = DatatableTable('user_table', model=UserModel)
        add_user_columns(table)
        table.ajax_data = False
        return {'table': table}
