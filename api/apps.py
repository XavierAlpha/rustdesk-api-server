from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class ApiConfig(AppConfig):
    name = 'api'
    verbose_name = _("Camellia 管理")

    def ready(self):
        # Ensure admin template probes don't emit debug warnings in Django 5+.
        try:
            from django.contrib.admin import helpers as admin_helpers
            if not hasattr(admin_helpers.AdminReadonlyField, "is_fieldset"):
                admin_helpers.AdminReadonlyField.is_fieldset = False
        except Exception:
            # Admin may not be installed or ready yet; ignore.
            pass
