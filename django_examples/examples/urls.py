from django.urls import path
from django.views.generic.base import RedirectView

from modal_2fa.user_admin import UserTable, UserAdminModal
import examples.views as views

urlpatterns = [
    path('Basic', views.Basic.as_view(), name='basic'),
    path('', RedirectView.as_view(url='Basic')),
    path('user-table', UserTable.as_view()),
    path('user-admin-modal/', UserAdminModal.as_view(), name='user_admin_modal'),
]
