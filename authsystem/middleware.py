from django.core.cache import cache
from django.shortcuts import render
from django.utils.deprecation import MiddlewareMixin
import time
from .models import ActivityLog
from threatintel.models import ThreatIP
from monitor.models import Alert

class ThreatIntelMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = request.META.get("REMOTE_ADDR")

        if ThreatIP.objects.filter(ip=ip).exists():
            Alert.objects.create(
                severity="High",
                message=f"User login attempt from blacklisted IP {ip}"
            )

        return self.get_response(request)


EXEMPT_PATH_PREFIXES = (
    "/static/", "/media/", "/admin/", "/favicon.ico", "/_next/", "/api/",
)


class ActivityLoggingMiddleware(MiddlewareMixin):
    """
    Logs all page views except static files/admin/ajax.
    Only logs authenticated users.
    """

    def process_view(self, request, view_func, view_args, view_kwargs):
        path = request.path

        # Skip exempt paths
        for prefix in EXEMPT_PATH_PREFIXES:
            if path.startswith(prefix):
                return None

        # Skip AJAX requests
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            return None

        if request.user.is_authenticated:
            ActivityLog.objects.create(
                user=request.user,
                event="PAGE_VIEW",
                path=path,
                ip_address=self._get_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
            )

        return None

    def _get_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "")
class LoginRateLimitMiddleware(MiddlewareMixin):

    MAX_ATTEMPTS = 5
    BLOCK_TIME = 300  # 5 minutes

    def process_view(self, request, view_func, view_args, view_kwargs):

        if request.path == "/login/" and request.method == "POST":

            ip = self.get_client_ip(request)
            key = f"login_attempts_{ip}"

            attempts = cache.get(key, {"count": 0, "last_attempt": time.time()})

            # If blocked
            if attempts["count"] >= self.MAX_ATTEMPTS:
                remaining = self.BLOCK_TIME - (time.time() - attempts["last_attempt"])
                if remaining > 0:
                    return render(request, "authsystem/login.html", {
                        "error": "Too many failed attempts. Try again in 5 minutes."
                    })
                else:
                    # Reset block
                    attempts = {"count": 0, "last_attempt": time.time()}

            # Store attempts for later — actual increment happens on failure inside login view
            cache.set(key, attempts, timeout=self.BLOCK_TIME)

        return None

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
