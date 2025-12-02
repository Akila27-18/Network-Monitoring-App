from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from authsystem.utils import log_event


from .forms import EmailLoginForm, RegisterForm
from .models import CustomUser
from .tokens import email_verification_token
from django.contrib.auth import logout
# authsystem/views.py  (append at bottom)
from django.core.paginator import Paginator
from django.db.models import Q
from django.contrib.auth.decorators import user_passes_test
from .models import ActivityLog

def logout_view(request):
    log_event(request.user, "LOGOUT", request)
    logout(request)
    return redirect("login")



# ---------------------------
# EMAIL VERIFICATION
# ---------------------------
def email_verify_view(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user = None

    if user and email_verification_token.check_token(user, token):
        user.email_verified = True
        user.save()
        return render(request, "authsystem/email_verification_success.html")

    return render(request, "authsystem/email_verification_failure.html")


# ---------------------------
# REGISTRATION
# ---------------------------
def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.email_verified = False
            user.save()

            # Encode UID and generate token
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            token = email_verification_token.make_token(user)

            verification_url = request.build_absolute_uri(
                reverse("email_verify", kwargs={"uidb64": uidb64, "token": token})
            )

            # Send verification email
            subject = "Verify your email for Network Monitor"
            message = (
                f"Hi {user.email},\n\n"
                f"Please verify your email by clicking the link below:\n{verification_url}\n\n"
                "Thank you!"
            )
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])

            return render(
                request,
                "authsystem/email_verification_sent.html",
                {"email": user.email}
            )
    else:
        form = RegisterForm()

    return render(request, "authsystem/register.html", {"form": form})


# ---------------------------
# LOGIN
# ---------------------------
def login_view(request):
    if request.method == "POST":
        form = EmailLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data["email"]
            password = form.cleaned_data["password"]
            remember = form.cleaned_data["remember_me"]

            user = authenticate(request, username=email, password=password)

            if user:
                if not user.email_verified:
                    # Logging unverified email login attempt
                    log_event(user, "LOGIN_FAILED", request, extra="Email not verified")
                    return render(
                        request,
                        "authsystem/login.html",
                        {"form": form, "error": "Email not verified. Please check your inbox."},
                    )

                # Successful login
                login(request, user)
                request.session.set_expiry(1209600 if remember else 0)

                log_event(user, "LOGIN", request)  # <-- success log

                return redirect("monitor:dashboard")

            # -------------------------------
            # INVALID CREDENTIALS BLOCK
            # -------------------------------

            # Log failed attempt
            log_event(None, "LOGIN_FAILED", request, extra=f"Email tried: {email}")

            # Increase rate-limit attempt count
            from django.core.cache import cache
            import time

            ip = request.META.get("REMOTE_ADDR")
            key = f"login_attempts_{ip}"

            attempts = cache.get(key, {"count": 0, "last_attempt": time.time()})
            attempts["count"] += 1
            attempts["last_attempt"] = time.time()
            cache.set(key, attempts, timeout=300)  # 5 minutes

            return render(
                request,
                "authsystem/login.html",
                {"form": form, "error": "Invalid email or password"},
            )

    else:
        form = EmailLoginForm()

    return render(request, "authsystem/login.html", {"form": form})


# ---------------------------
# GET CLIENT IP
# ---------------------------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")


def is_admin_user(user):
    return user.is_authenticated and (user.role == "admin" or user.is_superuser)

@user_passes_test(is_admin_user, login_url="login")
def activity_logs_view(request):
    qs = ActivityLog.objects.select_related("user").all()

    # Filters via GET params
    q = request.GET.get("q", "").strip()
    event = request.GET.get("event", "").strip()
    user_email = request.GET.get("user", "").strip()
    date_from = request.GET.get("from", "").strip()
    date_to = request.GET.get("to", "").strip()

    if q:
        qs = qs.filter(Q(path__icontains=q) | Q(extra__icontains=q) | Q(ip_address__icontains=q))
    if event:
        qs = qs.filter(event=event)
    if user_email:
        qs = qs.filter(user__email__icontains=user_email)
    if date_from:
        qs = qs.filter(timestamp__date__gte=date_from)
    if date_to:
        qs = qs.filter(timestamp__date__lte=date_to)

    paginator = Paginator(qs, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    # event choices for filter dropdown
    event_choices = ActivityLog.EVENT_CHOICES

    return render(request, "authsystem/activity_logs.html", {
        "page_obj": page_obj,
        "event_choices": event_choices,
        "filters": {"q": q, "event": event, "user": user_email, "from": date_from, "to": date_to},
    })
