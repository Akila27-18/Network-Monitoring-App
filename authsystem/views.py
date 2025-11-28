from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.core.cache import cache
from django.core.mail import send_mail
from django.urls import reverse
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes

from .forms import EmailLoginForm, RegisterForm
from .models import CustomUser
from .tokens import email_verification_token
from django.contrib.auth import logout

def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to login page after logout


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
                    return render(
                        request,
                        "authsystem/login.html",
                        {"form": form, "error": "Email not verified. Please check your inbox."},
                    )

                login(request, user)
                request.session.set_expiry(1209600 if remember else 0)

                print(f"Logged in user role: {user.role}")  # <-- debug

                return redirect("dashboard")

            return render(request, "authsystem/login.html", {"form": form, "error": "Invalid email or password"})
    else:
        form = EmailLoginForm()

    return render(request, "authsystem/login.html", {"form": form})



# ---------------------------
# GET CLIENT IP
# ---------------------------
def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")
