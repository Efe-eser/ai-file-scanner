from pathlib import Path
import os
from dotenv import load_dotenv
 
# 🔥 .env yükle
load_dotenv()
 
BASE_DIR = Path(__file__).resolve().parent.parent
 
STATIC_URL = '/static/'
 
STATICFILES_DIRS = [
    BASE_DIR / "static",
]
 
# 🔐 SECRET KEY (.env'den çekiyoruz)
SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-dev-key")
 
# ⚠️ DEBUG (env'den okunur; production'da DEBUG=False ayarla)
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
 
# 🌐 HOSTS (env'den virgülle ayrılmış host listesi; default: localhost)
ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]
 
 
# -----------------------------
# APPLICATIONS
# -----------------------------
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
 
    'rest_framework',
    'scanner',
    "corsheaders",
]
 
 
# -----------------------------
# MIDDLEWARE
# -----------------------------
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
 
 
ROOT_URLCONF = 'config.urls'
 
 
# -----------------------------
# TEMPLATES
# -----------------------------
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
 
        # hem app içi hem global templates çalışır
        'DIRS': [BASE_DIR / 'templates'],
 
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
 
 
WSGI_APPLICATION = 'config.wsgi.application'
 
 
# -----------------------------
# DATABASE
# -----------------------------
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}
 
 
# -----------------------------
# PASSWORD VALIDATION
# -----------------------------
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
 
 
# -----------------------------
# INTERNATIONALIZATION
# -----------------------------
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
 
USE_I18N = True
USE_TZ = True
 
 
# -----------------------------
# STATIC FILES
# -----------------------------
STATIC_URL = 'static/'
 
 
# -----------------------------
# DEFAULT FIELD
# -----------------------------
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
 
 
# -----------------------------
# CUSTOM ENV VARIABLES
# -----------------------------
# 🔥 VirusTotal API Key
VT_API_KEY = os.getenv("VT_API_KEY")
 
# 🌍 CORS (env'den virgülle ayrılmış origin listesi; boşsa hiçbir origin'e izin verilmez)
_cors_env = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env else []
# Dev kolaylığı: DEBUG açıkken her origin'e izin ver
CORS_ALLOW_ALL_ORIGINS = DEBUG
