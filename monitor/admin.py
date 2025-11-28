from django.contrib import admin
from authsystem.models import CustomUser

class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'role', 'email_verified', 'is_staff')

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        # Allow full access to superusers and admins
        if request.user.is_superuser or request.user.role == 'admin':
            return qs
        # Non-admin users see nothing
        return qs.none()

admin.site.register(CustomUser, CustomUserAdmin)
