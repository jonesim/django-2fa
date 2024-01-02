from django.contrib.admin.apps import AdminConfig


class AdminConfig2fa(AdminConfig):
    default = False
    default_site = 'modal_2fa.admin_site.AdminSite2FA'
