from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),

    # Authsystem URLs (login, register, email verification)
    path('', include('authsystem.urls')),  # e.g., /login/, /register/, /verify/<uid>/<token>/

    # Monitor app URLs under /monitor/ prefix
    path('monitor/', include('monitor.urls')),  # /monitor/dashboard/, /monitor/logs/, /monitor/alerts/

    # Redirect root URL to dashboard
    path('', lambda request: redirect('dashboard')),
]
