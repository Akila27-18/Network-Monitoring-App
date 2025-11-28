from django.shortcuts import redirect
from django.http import HttpResponseForbidden
from functools import wraps

def role_required(allowed_roles=None):
    if allowed_roles is None:
        allowed_roles = []

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user = request.user
            if not user.is_authenticated:
                return redirect('login')
            if allowed_roles and user.role not in allowed_roles:
                return HttpResponseForbidden(
                    "<h1>403 - Access Denied</h1>"
                    "<p>You do not have permission to access this page.</p>"
                )
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator
