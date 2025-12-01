# authsystem/signals.py
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.models import Session
from django.shortcuts import get_object_or_404

from .models import ActivityLog

def _get_ip_from_request(request):
    if not request:
        return ""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")

def _get_user_agent(request):
    if not request:
        return ""
    return request.META.get("HTTP_USER_AGENT", "")[:500]


@receiver(user_logged_in)
def log_user_logged_in(sender, request, user, **kwargs):
    ActivityLog.objects.create(
        user=user,
        event="LOGIN",
        path=request.path if request else "",
        ip_address=_get_ip_from_request(request),
        user_agent=_get_user_agent(request),
        extra=f"Session key: {getattr(request.session, 'session_key', '')}"
    )


@receiver(user_logged_out)
def log_user_logged_out(sender, request, user, **kwargs):
    # user may be None in some cases
    ActivityLog.objects.create(
        user=user if user and getattr(user, 'is_authenticated', False) else None,
        event="LOGOUT",
        path=request.path if request else "",
        ip_address=_get_ip_from_request(request),
        user_agent=_get_user_agent(request),
    )


@receiver(user_login_failed)
def log_user_login_failed(sender, credentials, request, **kwargs):
    # credentials is dict with 'email' or 'username' keys — never log password
    attempted = credentials.get("email") or credentials.get("username") or ""
    ActivityLog.objects.create(
        user=None,
        event="LOGIN_FAILED",
        path=request.path if request else "",
        ip_address=_get_ip_from_request(request),
        user_agent=_get_user_agent(request),
        extra=f"attempted={attempted}"
    )
