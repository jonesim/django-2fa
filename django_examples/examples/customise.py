from modal_2fa.customise import CustomiseAuth
from django.utils.safestring import mark_safe
from django_modals.form_helpers import SmallHelper


class ExampleCustomise(CustomiseAuth):

    @staticmethod
    def customise_view(view):
        view.center_header = True
        view.size = 'md'
        view.helper_class = SmallHelper
        if hasattr(view, 'modal_title'):
            image = '<img src="/static/HTML5.svg" width="28">'
            view.modal_title = mark_safe(
                f'<span class="m-auto">{image}<span class="ml-2">{view.modal_title}</span></span>'
            )
        view.no_parent_template = 'blank_page_img.html'

    @staticmethod
    def allowed_remember(user):
        if user.username == 'ian5':
            return False
        return True

    @staticmethod
    def user_2fa_optional(user):
        return True
