"""The fake Wagtail admin mounted *above* the modal_2fa include.

The wrong order: Wagtail's own login wins the URL resolution, so the shadow
patterns never run. Wagtail2FAMiddleware must refuse to start rather than gate
the admin around a still-reachable unauthenticated login.
"""

from django.urls import include, path

from examples.tests import WagtailCustomise
from examples.wagtail_test_urls import fake_wagtail_admin

urlpatterns = [
    path('cms/', include(fake_wagtail_admin)),
    path('', include(WagtailCustomise.paths())),
]
