from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from ajax_helpers.mixins import AjaxHelpers
from django_menus.menu import MenuMixin
from modal_2fa.menus import add_auth_menu


class MainMenu(AjaxHelpers, MenuMixin):
    template_name = 'demo.html'

    def setup_menu(self):
        self.add_menu('main_menu').add_items(('basic', 'Two Factor Demo'), )
        add_auth_menu(self)


class MainMenuTemplateView(MainMenu, TemplateView):
    pass


class Basic(MainMenuTemplateView):

    template_name = 'example.html'

    def setup_menu(self):
        super().setup_menu()


class ProtectedPage(LoginRequiredMixin, Basic):

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['page_title'] = 'Protected Page'
        return context
