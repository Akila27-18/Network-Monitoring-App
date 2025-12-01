# authsystem/utils.py
from .models import ActivityLog

def log_event(user, event, request, extra=None):
    ActivityLog.objects.create(
        user=user,
        event=event,
        path=request.path,
        ip_address=_get_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", "")[:500],
        extra=extra or "",
    )

def _get_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")
