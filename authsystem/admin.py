# authsystem/admin.py  (append)
from django.contrib import admin
from .models import ActivityLog

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "event", "ip_address", "path")
    list_filter = ("event", "timestamp", "user")
    search_fields = ("user__email", "ip_address", "path", "extra")
    readonly_fields = ("timestamp",)
    ordering = ("-timestamp",)
