from django.contrib import admin
from django.urls import path, include
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),

    # Authsystem URLs (login/register/etc)
    path('', include('authsystem.urls')),

    # Monitor app - mounted under /monitor/
    path('monitor/', include('monitor.urls')),

    # Threat intel app
    path('threats/', include('threatintel.urls')),

    # Legacy: redirect root to dashboard
    path('', lambda request: redirect('monitor:dashboard')),
]
