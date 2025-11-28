from django.core.cache import cache
from django.shortcuts import render
from django.utils.deprecation import MiddlewareMixin
import time

class LoginRateLimitMiddleware(MiddlewareMixin):

    MAX_ATTEMPTS = 5
    BLOCK_TIME = 300  # 5 mins

    def process_view(self, request, view_func, view_args, view_kwargs):

        # Apply only to login POST
        if request.path == "/login/" and request.method == "POST":

            ip = self.get_client_ip(request)
            key = f"login_attempts_{ip}"

            attempts = cache.get(key, {"count": 0, "last_attempt": time.time()})

            # If blocked
            if attempts["count"] >= self.MAX_ATTEMPTS:
                if time.time() - attempts["last_attempt"] < self.BLOCK_TIME:
                    return render(request, "authsystem/login.html", {
                        "error": "Too many login attempts. Try again in 5 minutes."
                    })
                else:
                    # Reset after block expires
                    attempts = {"count": 0, "last_attempt": time.time()}

            # Update attempt count
            attempts["count"] += 1
            attempts["last_attempt"] = time.time()
            cache.set(key, attempts, timeout=self.BLOCK_TIME)

        return None

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")
