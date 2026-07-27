import os
from pathlib import Path

import django
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
DJANGO_FORMS_TEMPLATES = Path(django.__file__).resolve().parent / 'forms' / 'templates'


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on", "y")


def env_csv(name, default=None):
    value = os.environ.get(name, "").strip()
    if not value:
        return list(default or [])
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def env_int(name, default, min_value=None, max_value=None):
    try:
        value = int(os.environ.get(name, str(default)).strip())
    except ValueError:
        value = default
    if min_value is not None and value < min_value:
        return default
    if max_value is not None and value > max_value:
        return default
    return value


DEBUG = env_bool("DEBUG", False)
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "dev-only-insecure-secret-key"
    else:
        raise ImproperlyConfigured("SECRET_KEY must be set when DEBUG is false")

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
ALLOWED_HOSTS = env_csv("ALLOWED_HOSTS", ["127.0.0.1", "localhost"])
CSRF_TRUSTED_ORIGINS = env_csv("CSRF_TRUSTED_ORIGINS", ["http://127.0.0.1:21114"])
# Relaxed so the bundled Flutter web client can complete popup-based OIDC flows.
SECURE_CROSS_ORIGIN_OPENER_POLICY = None

# Only enable behind a reverse proxy that overwrites X-Forwarded-For / X-Real-IP;
# otherwise clients can choose the address the login lockout is keyed on.
TRUST_PROXY_HEADERS = env_bool("TRUST_PROXY_HEADERS", False)

# TLS-terminating deployments (reverse proxy or direct) should set SECURE_TLS=true.
_secure_tls = env_bool("SECURE_TLS", False)
SESSION_COOKIE_SECURE = _secure_tls
CSRF_COOKIE_SECURE = _secure_tls
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") if _secure_tls else None
SECURE_SSL_REDIRECT = _secure_tls
SECURE_HSTS_SECONDS = env_int(
    "SECURE_HSTS_SECONDS",
    31536000 if _secure_tls else 0,
    0,
    63072000,
)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", _secure_tls)
SECURE_HSTS_PRELOAD = env_bool("SECURE_HSTS_PRELOAD", _secure_tls)
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SESSION_COOKIE_HTTPONLY = True
AUTH_USER_MODEL = "api.UserProfile"

ID_SERVER = os.environ.get("ID_SERVER", "").strip()
API_SERVER = os.environ.get("API_SERVER", "").strip()
RS_PUB_KEY = os.environ.get("RS_PUB_KEY", "").strip()
RELAY_SERVER = os.environ.get("RELAY_SERVER", "").strip()
DEFAULT_ID_PORT = env_int("DEFAULT_ID_PORT", 21116, 1, 65535)
PLUGIN_SIGNING_KEY = os.environ.get("PLUGIN_SIGNING_KEY", "").strip()

OIDC_PROVIDERS = {}
_oidc_name = os.environ.get("OIDC_NAME", "").strip()
_oidc_issuer = os.environ.get("OIDC_ISSUER", "").strip()
_oidc_client_id = os.environ.get("OIDC_CLIENT_ID", "").strip()
_oidc_client_secret = os.environ.get("OIDC_CLIENT_SECRET", "").strip()
_oidc_redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "").strip()
if _oidc_name and _oidc_issuer and _oidc_client_id and _oidc_client_secret and _oidc_redirect_uri:
    OIDC_PROVIDERS[_oidc_name] = {
        "issuer": _oidc_issuer,
        "client_id": _oidc_client_id,
        "client_secret": _oidc_client_secret,
        "redirect_uri": _oidc_redirect_uri,
        "scope": os.environ.get("OIDC_SCOPE", "openid email profile"),
    }

ALLOW_REGISTRATION = env_bool("ALLOW_REGISTRATION", False)

# Recording uploads contain highly sensitive session data. Keep each request
# bounded before Django materializes request.body, and cap the resulting file so
# a valid but compromised device session cannot exhaust the server volume.
RECORD_UPLOAD_MAX_CHUNK_BYTES = env_int(
    "RECORD_UPLOAD_MAX_CHUNK_BYTES",
    4 * 1024 * 1024,
    64 * 1024,
    64 * 1024 * 1024,
)
RECORD_UPLOAD_MAX_FILE_BYTES = env_int(
    "RECORD_UPLOAD_MAX_FILE_BYTES",
    10 * 1024 * 1024 * 1024,
    RECORD_UPLOAD_MAX_CHUNK_BYTES,
    1024 * 1024 * 1024 * 1024,
)
RECORD_UPLOAD_ROOT = Path(os.environ.get("RECORD_UPLOAD_ROOT", BASE_DIR / "records"))
DATA_UPLOAD_MAX_MEMORY_SIZE = RECORD_UPLOAD_MAX_CHUNK_BYTES


# ==========数据库配置 开始=====================
DATABASE_TYPE = os.environ.get("DATABASE_TYPE", "SQLITE").upper()
MYSQL_DBNAME = os.environ.get("MYSQL_DBNAME", "-")
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_USER = os.environ.get("MYSQL_USER", "-")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "-")
MYSQL_PORT = os.environ.get("MYSQL_PORT", "3306")
SQLITE_DB_PATH = os.environ.get("SQLITE_DB_PATH", "")
# ==========数据库配置 结束=====================

LANGUAGE_CODE = os.environ.get("LANGUAGE_CODE", "zh-hans")

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'api.apps.ApiConfig',
    'webui2.apps.Webui2Config',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'rustdesk_server_api.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates', DJANGO_FORMS_TEMPLATES],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'api.util.settings',
            ],
        },
    },
]
FORM_RENDERER = 'django.forms.renderers.TemplatesSetting'

WSGI_APPLICATION = 'rustdesk_server_api.wsgi.application'


sqlite_name = SQLITE_DB_PATH if SQLITE_DB_PATH else (BASE_DIR / "db/db.sqlite3")
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": sqlite_name,
    }
}
if DATABASE_TYPE == "MYSQL" and MYSQL_DBNAME != "-" and MYSQL_USER != "-" and MYSQL_PASSWORD != "-":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.mysql",
            "NAME": MYSQL_DBNAME,
            "HOST": MYSQL_HOST,
            "USER": MYSQL_USER,
            "PASSWORD": MYSQL_PASSWORD,
            "PORT": MYSQL_PORT,
            "OPTIONS": {"charset": "utf8mb4"},
        }
    }

# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

# LANGUAGE_CODE = 'zh-hans'

TIME_ZONE = os.environ.get("TIME_ZONE", "Asia/Shanghai")

USE_I18N = True

USE_TZ = True

# ==========日志配置 开始=====================
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_LEVEL = LOG_LEVEL if LOG_LEVEL in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "[{asctime}] {levelname} {name}: {message}",
            "style": "{",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": LOG_LEVEL,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
        "api": {"handlers": ["console"], "level": LOG_LEVEL, "propagate": False},
    },
}
# ==========日志配置 结束=====================


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "static_root"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

MEDIA_ROOT = BASE_DIR / "records"
MEDIA_URL = "/records/"

LANGUAGES = (
    ('zh-hans', '中文简体'),
    ('en', 'English'),

)

LOCALE_PATHS = (
    os.path.join(BASE_DIR, 'locale'),
)
