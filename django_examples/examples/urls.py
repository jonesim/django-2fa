from django.urls import path
from django.views.generic.base import RedirectView

from modal_2fa.user_admin import UserTable
import examples.views as views

urlpatterns = [
    path('', RedirectView.as_view(url='Basic')),
    path('Basic/', views.Basic.as_view(), name='basic'),
    path('Protected/', views.ProtectedPage.as_view(), name='protected'),
    path('user-table/', UserTable.as_view()),
]
