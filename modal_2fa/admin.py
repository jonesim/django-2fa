from django.contrib import admin

from modal_2fa.models import RememberDeviceCookie, WebauthnCredentials


@admin.register(RememberDeviceCookie)
class RememberDeviceCookieAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'active', 'last_used')
    readonly_fields = ('last_used', 'created')


@admin.register(WebauthnCredentials)
class WebauthnCredentialsAdmin(admin.ModelAdmin):
    pass
