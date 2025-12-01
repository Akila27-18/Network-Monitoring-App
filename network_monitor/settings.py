"""
Django settings for network_monitor project.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------
# SECURITY
# --------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
DEBUG = os.environ.get("RENDER", None) is None  # Debug ON locally, OFF on Render
ALLOWED_HOSTS = ["*", ".onrender.com"]

CSRF_TRUSTED_ORIGINS = ["https://*.onrender.com"]
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --------------------------------------------------------------------
# APPS
# --------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    "authsystem",
    "threatintel",
    "monitor",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # <-- REQUIRED FOR RENDER

    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",

    "authsystem.middleware.LoginRateLimitMiddleware",
    "authsystem.middleware.ActivityLoggingMiddleware",
    "authsystem.middleware.ThreatIntelMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
]

ROOT_URLCONF = "network_monitor.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "network_monitor.wsgi.application"

# --------------------------------------------------------------------
# DATABASE (SQLite on Render persistent disk)
# --------------------------------------------------------------------
RENDER_DB_DIR = "/opt/render/project/db"
os.makedirs(RENDER_DB_DIR, exist_ok=True)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(RENDER_DB_DIR, "db.sqlite3"),
    }
}

# --------------------------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------------------------
AUTH_USER_MODEL = "authsystem.CustomUser"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --------------------------------------------------------------------
# LOCALIZATION
# --------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = False

# --------------------------------------------------------------------
# STATIC FILES (Render + Whitenoise)
# --------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# --------------------------------------------------------------------
# CACHING
# --------------------------------------------------------------------
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-snowflake",
    }
}

# --------------------------------------------------------------------
# EMAIL
# --------------------------------------------------------------------
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "akila271819@gmail.com"
EMAIL_HOST_PASSWORD = "wqtoeiyqiwpwxsam"  # Gmail APP PASSWORD
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# --------------------------------------------------------------------
# SESSIONS
# --------------------------------------------------------------------
SESSION_ENGINE = "django.contrib.sessions.backends.db"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
