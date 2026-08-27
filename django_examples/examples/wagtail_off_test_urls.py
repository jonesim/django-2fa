"""The same fake Wagtail admin, but with a CustomiseAuth that sets no prefix.

urlpatterns are built once at import, so proving "nothing is registered unless
wagtail_admin_prefix is set" needs its own ROOT_URLCONF module.
"""

from modal_2fa.customise import CustomiseAuth

from examples.wagtail_test_urls import make_urlpatterns

urlpatterns = make_urlpatterns(CustomiseAuth)
