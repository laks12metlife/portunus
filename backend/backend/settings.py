import json
import os
import environ
import boto3
import sentry_sdk
from datetime import timedelta

from sentry_sdk.integrations.django import DjangoIntegration
from zygoat_django.settings import *  # noqa
from zygoat_django.settings import prod_required_env, PRODUCTION, DEBUG, REST_FRAMEWORK

env = environ.Env()

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_secret(secret_arn):
    """Create a Secrets Manager client"""
    client = boto3.client("secretsmanager")
    get_secret_value_response = client.get_secret_value(SecretId=secret_arn)
    return get_secret_value_response


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = prod_required_env(
    "DJANGO_SECRET_KEY", default="1EJjhdOOqcnEU4ybJFEMo1jBpWmuv44YObROluFTEWc="
)
if "DJANGO_SECRET_KEY" in os.environ and PRODUCTION:
    django_secret_key = json.loads(get_secret(os.environ["DJANGO_SECRET_KEY"])["SecretString"])
    SECRET_KEY = django_secret_key["DJANGO_SECRET_KEY"]


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "backend",
    "willing_zg",
    "authentication",
    "rest_framework_simplejwt.token_blacklist",
    "axes",
    "zygoat_django",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "axes.middleware.AxesMiddleware",
    "zygoat_django.middleware.ReverseProxyHandlingMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "zygoat_django.middleware.session_expiration_middleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "backend.urls"

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

WSGI_APPLICATION = "backend.wsgi.application"


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases

if "DATABASE_SECRET" in os.environ:
    db_secret = json.loads(get_secret(os.environ["DATABASE_SECRET"])["SecretString"])

    db_username = db_secret["username"]
    db_password = db_secret["password"]
    db_host = db_secret["host"]
    db_port = str(db_secret["port"])
    db_clusterid = db_secret["dbClusterIdentifier"]

    db_url = f"postgres://{db_username}:{db_password}@{db_host}:{db_port}/{db_clusterid}"
    os.environ["DATABASE_URL"] = db_url


db_config = env.db_url("DATABASE_URL", default="postgres://postgres:postgres@db/postgres")

DATABASES = {"default": db_config}


# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 8,
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
    {
        "NAME": "authentication.password_validators.AlphaNumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.0/howto/static-files/

STATIC_URL = "/static/"


# Cookies
SHARED_DOMAIN = prod_required_env("DJANGO_SHARED_DOMAIN", default=None)
CSRF_COOKIE_DOMAIN = SHARED_DOMAIN
CSRF_TRUSTED_ORIGINS = SHARED_DOMAIN and [f".{SHARED_DOMAIN}"]
SESSION_COOKIE_DOMAIN = SHARED_DOMAIN
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"
SESSION_COOKIE_AGE = 3600
CSRF_COOKIE_AGE = SESSION_COOKIE_AGE
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_EXPIRE_AT_BROWSER_CLOSE = True


# Set security headers
X_FRAME_OPTIONS = "DENY"
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True


REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"] = (
    "simplejwt_extensions.authentication.JWTAuthentication",
)

# production must use SMTP. others will use DJANGO_EMAIL_BACKEND or default to "console"
EMAIL_BACKEND = "django.core.mail.backends.{}.EmailBackend".format(
    env.str("DJANGO_EMAIL_BACKEND", default="console") if DEBUG else "smtp"
)
EMAIL_HOST = "email-smtp.us-east-1.amazonaws.com"
EMAIL_PORT = 587
EMAIL_HOST_USER = prod_required_env("DJANGO_EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = prod_required_env("DJANGO_EMAIL_HOST_PASSWORD", "")
if "DJANGO_EMAIL_HOST_PASSWORD" in os.environ:
    django_password = json.loads(
        get_secret(os.environ["DJANGO_EMAIL_HOST_PASSWORD"])["SecretString"]
    )
    EMAIL_HOST_PASSWORD = django_password["DJANGO_EMAIL_HOST_PASSWORD"]

EMAIL_USE_TLS = True

SUPPORT_PHONE_NUMBER = "+1 (855) 943-4177"
SUPPORT_EMAIL_ADDRESS = "clientservice@legalplans.com"
PANEL_EMAIL_ADDRESS = "panel@legalplans.com"

DEFAULT_VERIFYING_KEY = """MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC91RWCawEvxQj+tigRvuHxouO8
jKd35ukUxFBFRAGcI57firbAkFII6zPIiWAENGMqtjX57hk9EjAZ27XvQ4SQACvD
5j7htsJT31bZbVUH7a3JEDpxa02VXpXdfPYSs8umZkdxMxxmiD9uH9VmLN3VS14l
xQlyJdlvbLmNCAf6uwIDAQAB"""

NAKED_VERIFYING_KEY = prod_required_env("DJANGO_JWT_VERIFYING_KEY", DEFAULT_VERIFYING_KEY)

if "DJANGO_JWT_VERIFYING_KEY" in os.environ and PRODUCTION:
    NAKED_VERIFYING_KEY = json.loads(
        get_secret(os.environ["DJANGO_JWT_VERIFYING_KEY"])["SecretString"]
    )["DJANGO_JWT_VERIFYING_KEY"]


VERIFYING_KEY = f"""-----BEGIN PUBLIC KEY-----
{NAKED_VERIFYING_KEY.replace(" ", "")}
-----END PUBLIC KEY-----"""

SIMPLE_JWT = {
    "USER_ID_FIELD": "public_id",
    "ALGORITHM": "RS512",
    "SIGNING_KEY": None,
    "VERIFYING_KEY": VERIFYING_KEY,
}

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}

AUTH_USER_MODEL = "authentication.User"

AUTHENTICATION_BACKENDS = [
    # AxesBackend should be the first backend in the AUTHENTICATION_BACKENDS list.
    "axes.backends.AxesBackend",
    "django.contrib.auth.backends.ModelBackend",
]

AXES_FAILURE_LIMIT = env.int("DJANGO_AXES_FAILURE_LIMIT", default=5)
AXES_USERNAME_FORM_FIELD = "email"
AXES_RESET_ON_SUCCESS = True
AXES_ONLY_USER_FAILURES = True
AXES_USERNAME_CALLABLE = "authentication.utils.get_username"
AXES_LOCKOUT_CALLABLE = "authentication.utils.generate_axes_lockout_response"

DEFAULT_SIGNING_KEY = """MIICXQIBAAKBgQC91RWCawEvxQj+tigRvuHxouO8jKd35ukUxFBFRAGcI57firbA
kFII6zPIiWAENGMqtjX57hk9EjAZ27XvQ4SQACvD5j7htsJT31bZbVUH7a3JEDpx
a02VXpXdfPYSs8umZkdxMxxmiD9uH9VmLN3VS14lxQlyJdlvbLmNCAf6uwIDAQAB
AoGACXFcDIy+Fl46wFDXVWqlWpu7sFleyzwVRA8v3wIvAlFTSdNgm9uR+ReaD9Ol
jw/8DtfZf4E0iDEra13egvRc16byYQ4qv0l7xvn3ATomxcPwbdvkfYE4C0EZFuXx
ZZwSQwWsNl/36BSyZErw8y/THMIkOKRNFuJarK4P3aYppEECQQDpvRnL2kbbXbqW
uB8Pt2hMfBXW/byCcctoI+cuqYAUJ/J1tLPe+q7sAW6Fr0WpYTpjljC+UCqu/a6a
YgG0L6I5AkEAz+l7QfyFKk7jl05hEUly0CNshgJ8jLPcF2ZXILrcUwGxbpdyjmCJ
ExiKpfzPufYeu7qLwhyaHniR9huSZIx0kwJBALMRTFIAR4iHpgsRw7omqKDv70tl
2KWWyF5gIxx8fsLyV64VYjfRlXD5J9MDFDtPYYwp4+3pPMoTT1C3BNcmJwECQEYV
Ero0b4LKYsce4XNdSblFJ5Coh+k5u2eb1KSwuBG20WNQ44mAmtP4AsxewnqRrtxi
zjdZQs4goDrQInGIMscCQQCIT5jvRb197iRinBqpNy01i7GdlLtMC7Z9V/PV0YW1
GmX50gvd7aA+i2UuZj7BxapFStyEGl4Nggglnn+QqQ+L"""

NAKED_SIGNING_KEY = prod_required_env("DJANGO_JWT_SIGNING_KEY", DEFAULT_SIGNING_KEY)

if "DJANGO_JWT_SIGNING_KEY" in os.environ and PRODUCTION:
    NAKED_SIGNING_KEY = json.loads(
        get_secret(os.environ["DJANGO_JWT_SIGNING_KEY"])["SecretString"]
    )["DJANGO_JWT_SIGNING_KEY"]
SIGNING_KEY = f"""-----BEGIN RSA PRIVATE KEY-----
{NAKED_SIGNING_KEY.replace(" ", "")}
-----END RSA PRIVATE KEY-----"""

# Override the values set by willing-zg simple jwt plugin
SIMPLE_JWT["USER_ID_FIELD"] = "portunus_uuid"
SIMPLE_JWT["SIGNING_KEY"] = SIGNING_KEY
SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"] = timedelta(hours=1)

CORS_ORIGIN_ALLOW_ALL = DEBUG
CORS_ALLOW_CREDENTIALS = True
if not DEBUG:
    CORS_ORIGIN_REGEX_WHITELIST = [
        r"^https://[\w.]+\.willing\.com$",
        r"^https://[\w.]+\.legalplans\.com$",
    ]

BASE_URL = env("DJANGO_BASE_URL", default="http://localhost:3001/")

DEFAULT_REDIRECT_URL = prod_required_env(
    "DJANGO_DEFAULT_REDIRECT_URL", "http://localhost:3001"
)
VALID_REDIRECT_HOSTNAMES = ["*.willing.com", "*.legalplans.com"]

if not PRODUCTION:
    VALID_REDIRECT_HOSTNAMES.append("localhost")

SESSION_COOKIE_SAMESITE = None

# Sentry
SENTRY_DSN = prod_required_env("DJANGO_SENTRY_DSN", default=None)
ENVIRONMENT = prod_required_env("DJANGO_ENVIRONMENT", default=None)

if SENTRY_DSN is not None:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        integrations=[DjangoIntegration()],
        send_default_pii=True,
        environment=ENVIRONMENT,
    )

GOOGLE_CAPTCHA_SECRET_KEY = prod_required_env(
    "GOOGLE_CAPTCHA_SECRET_KEY", default="6Ldof8kZAAAAAB69zPnBf0og7OZyiRzlzmApOhSX"
)
GOOGLE_CAPTCHA_SITE_KEY = prod_required_env(
    "GOOGLE_CAPTCHA_SITE_KEY", default="6Ldof8kZAAAAAKdQfBfgJQ8Ogbr-esIgLj9K8tYH"
)

ZYGOAT_FRONTEND_META_CONFIG = {
    "sentry_dsn": prod_required_env(
        "DJANGO_FRONTEND_SENTRY_DSN",
        default="https://8db6b816b01548e0bacdb9bdbeb2caf8@o39628.ingest.sentry.io/5339664",
    ),
    "sentry_environment": ENVIRONMENT,
    "captcha_site_key": GOOGLE_CAPTCHA_SITE_KEY,
}

CELERY_BROKER_URL = CACHES["default"]["LOCATION"]
