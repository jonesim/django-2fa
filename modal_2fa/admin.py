from django.contrib import admin

from modal_2fa.models import RememberDeviceCookie, WebauthnCredential, FailedLoginAttempt


@admin.register(RememberDeviceCookie)
class RememberDeviceCookieAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'active', 'last_used')
    readonly_fields = ('last_used', 'created')


@admin.register(WebauthnCredential)
class WebauthnCredentialsAdmin(admin.ModelAdmin):
    list_display = ('user', 'rp_id')


@admin.register(FailedLoginAttempt)
class FailedLoginAttemptsAdmin(admin.ModelAdmin):
    list_display = ('user', 'ip_address', 'failed_attempts')
