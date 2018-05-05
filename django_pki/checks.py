from typing import List

from django.conf import settings
from django.apps import AppConfig
from django.core.checks import Error, register


@register()
def bootstrap4_check(app_configs: AppConfig, **kwargs) -> List[Error]:
    errors = []
    if 'bootstrap4' not in settings.INSTALLED_APPS:
        errors.append(
            Error('bootstrap4 needs to be in INSTALLED_APPS')
        )
    return errors
