from django.contrib.auth.models import AbstractUser
from django.db import models
from .managers import CustomUserManager

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

    objects = CustomUserManager()   # <-- IMPORTANT

    def __str__(self):
        return self.email
