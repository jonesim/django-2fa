"""Stand-in for a project that mounts Wagtail's admin, used by the Wagtail tests.

Wagtail itself isn't a dependency of the demo project, so the fake admin below
just reproduces the URL names and routes that matter: the shadowable auth entry
points plus a page behind them. The ordering mirrors django_examples/urls.py --
the modal_2fa include sits *above* the Wagtail one, which is the contract the
shadow patterns rely on.
"""

from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path

from examples.tests import WagtailCustomise


def stub_view(_request, **_kwargs):
    return HttpResponse('wagtail')


fake_wagtail_admin = [
    path('', stub_view, name='wagtailadmin_home'),
    path('login/', stub_view, name='wagtailadmin_login'),
    path('logout/', stub_view, name='wagtailadmin_logout'),
    path('pages/', stub_view, name='wagtailadmin_explore_root'),
    path('password_reset/', stub_view, name='wagtailadmin_password_reset'),
    path('password_reset/done/', stub_view, name='wagtailadmin_password_reset_done'),
    path('password_reset/confirm/<uidb64>/<token>/', stub_view, name='wagtailadmin_password_reset_confirm'),
    path('password_reset/complete/', stub_view, name='wagtailadmin_password_reset_complete'),
]


def make_urlpatterns(customise_cls):
    return [
        path('', include('examples.urls')),
        path('', include(customise_cls.paths())),
        path('cms/', include(fake_wagtail_admin)),
        # The auth menu rendered on ordinary pages reverses admin:index.
        path('admin/', admin.site.urls),
    ]


urlpatterns = make_urlpatterns(WagtailCustomise)
