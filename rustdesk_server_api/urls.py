"""rustdesk_server_api URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from pathlib import Path

from django.conf import settings
from django.conf.urls.static import static as static_urlpatterns
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.decorators.csrf import csrf_exempt
from django.views.static import serve as static_serve

from api import views_api
from api.views import index

CANVASKIT_ROOT = Path(settings.BASE_DIR) / "static" / "web_client" / "canvaskit@0.33.0"

urlpatterns = [
    path("i18n/", include("django.conf.urls.i18n")),
    path("admin/", admin.site.urls),
    re_path(r"^$", index),
    re_path(r"^api/", include("api.urls")),
    re_path(r"^lic/web/api/plugin-sign$", csrf_exempt(views_api.plugin_sign)),
    re_path(r"^webui2/", include("webui2.urls")),
    re_path(
        r"^static/(?P<path>.*)$",
        static_serve,
        {"document_root": settings.STATIC_ROOT},
        name="static",
    ),
    re_path(
        r"^canvaskit@0.33.0/(?P<path>.*)$",
        static_serve,
        {"document_root": str(CANVASKIT_ROOT)},
        name="web_client",
    ),
]

if not settings.DEBUG:
    urlpatterns += static_urlpatterns(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
