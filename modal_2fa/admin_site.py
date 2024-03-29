from django.contrib import admin
from django.http import HttpResponseRedirect

from modal_2fa.auth import ModalLoginView, auth_2fa_url


class AdminSite2FA(admin.AdminSite):

    def has_permission(self, request):
        return (request.user.is_active and request.user.is_staff and
                request.session.get('authentication_method') == '2fa')

    def login(self, request, extra_context=None):
        if request.user.is_active and request.user.is_staff and request.session.get('authentication_method') != '2fa':
            return HttpResponseRedirect(auth_2fa_url(request))
        return ModalLoginView.as_view()(request)
