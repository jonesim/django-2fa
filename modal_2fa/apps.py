from django.apps import AppConfig
from django.contrib.admin.apps import AdminConfig


class ModalConfig(AppConfig):
    name = 'modal_2fa'


class AdminConfig2fa(AdminConfig):
    default_site = 'modal_2fa.admin.AdminSite2FA'
