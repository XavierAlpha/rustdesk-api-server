from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class WebuiConfig(AppConfig):
    name = 'webui'
    verbose_name = _("网页控制台")
