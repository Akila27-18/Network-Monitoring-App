from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.db.models import Sum

from authsystem.forms import EmailLoginForm, RegisterForm
from authsystem.models import CustomUser 
from .models import NetworkLog, Alert
from authsystem.tokens import email_verification_token
from authsystem.decorators import role_required


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

            # Generate token & UID
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = email_verification_token.make_token(user)

            verification_url = request.build_absolute_uri(
                reverse("email_verify", kwargs={"uidb64": uid, "token": token})
            )

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
                    return render(
                        request,
                        "authsystem/login.html",
                        {
                            "form": form,
                            "error": "Email not verified. Please check your inbox."
                        },
                    )

                login(request, user)

                # Reset rate limit for this IP
                ip = get_client_ip(request)
                cache.delete(f"login_attempts_{ip}")

                # Remember me session
                request.session.set_expiry(1209600 if remember else 0)

                return redirect("dashboard")

            return render(
                request,
                "authsystem/login.html",
                {"form": form, "error": "Invalid email or password"},
            )
    else:
        form = EmailLoginForm()

    return render(request, "authsystem/login.html", {"form": form})


# ---------------------------
# LOGOUT
# ---------------------------
def logout_view(request):
    logout(request)
    return redirect("login")


# ---------------------------
# GET CLIENT IP
# ---------------------------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")


# ---------------------------
# DASHBOARD
# ---------------------------
@role_required()  # No roles specified → all logged-in users can see
def dashboard_view(request):
    user = request.user

    # Basic stats for all users
    total_logs = NetworkLog.objects.count()
    unique_ips = NetworkLog.objects.values("source_ip").distinct().count()

    # Role-specific stats
    if user.role in ['admin', 'analyst']:
        active_alerts = Alert.objects.filter(severity="High").count()
        # Traffic over time (last 7 logs)
        logs = NetworkLog.objects.order_by('-timestamp')[:7]
        timeline_labels = [log.timestamp.strftime("%H:%M") for log in logs]
        timeline_data = [log.bytes_transferred for log in logs]

        # Top 5 Source IPs
        top_ips = (
            NetworkLog.objects.values('source_ip')
            .annotate(total=Sum('bytes_transferred'))
            .order_by('-total')[:5]
        )
        top_ip_labels = [row['source_ip'] for row in top_ips]
        top_ip_values = [row['total'] for row in top_ips]

        latest_alerts = Alert.objects.order_by('-timestamp')[:5]
    else:
        # Viewer role sees limited info
        active_alerts = None
        timeline_labels = []
        timeline_data = []
        top_ip_labels = []
        top_ip_values = []
        latest_alerts = []

    context = {
        "total_logs": total_logs,
        "active_alerts": active_alerts,
        "unique_ips": unique_ips,
        "timeline_labels": timeline_labels,
        "timeline_data": timeline_data,
        "top_ip_labels": top_ip_labels,
        "top_ip_values": top_ip_values,
        "latest_alerts": latest_alerts,
    }

    return render(request, "monitor/dashboard.html", context)

# ---------------------------
# ALERTS VIEW
# ---------------------------
@role_required(['admin'])
def alerts_view(request):
    alerts = Alert.objects.order_by('-timestamp')
    return render(request, 'monitor/alerts.html', {"alerts": alerts})


# ---------------------------
# LOGS VIEW
# ---------------------------
@role_required(['admin', 'analyst', 'viewer'])
def logs_view(request):
    logs = NetworkLog.objects.order_by('-timestamp')
    return render(request, 'monitor/logs.html', {"logs": logs})
