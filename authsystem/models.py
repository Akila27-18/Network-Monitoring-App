from django.contrib.auth.models import AbstractUser
from django.db import models
from .managers import CustomUserManager
from django.conf import settings

class ActivityLog(models.Model):
    EVENT_CHOICES = [
        ("LOGIN", "User Login"),
        ("LOGIN_FAILED", "Login Failed"),
        ("LOGOUT", "User Logout"),
        ("PAGE_VIEW", "Page View"),
        ("ERROR", "Error"),
        ("CUSTOM", "Custom"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="activity_logs"
    )
    event = models.CharField(max_length=20, choices=EVENT_CHOICES)
    path = models.CharField(max_length=500, blank=True)
    ip_address = models.CharField(max_length=50, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    extra = models.TextField(blank=True)

    class Meta:
        ordering = ("-timestamp",)
        indexes = [
            models.Index(fields=["event"]),
            models.Index(fields=["timestamp"]),
            models.Index(fields=["user"]),
        ]

    def __str__(self):
        u = self.user.email if self.user else "Anonymous"
        return f"{self.timestamp} - {u} - {self.event}"


class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(unique=True)

    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('analyst', 'Analyst'),
        ('viewer', 'Viewer'),
    )

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    email_verified = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email
