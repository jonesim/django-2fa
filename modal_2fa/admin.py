from django.contrib import admin
from .models import *


@admin.register(RememberDeviceCookie)
class RememberDeviceCookieAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'active', 'last_used')
    readonly_fields = ('last_used',)
