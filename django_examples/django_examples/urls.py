from django.contrib import admin
from django.urls import include, path
from examples.customise import ExampleCustomise

urlpatterns = [
    path('', include('examples.urls')),
    path('', include(ExampleCustomise.paths())),
    path('admin/', admin.site.urls),
    path('src/', include('show_src_code.urls')),
]
