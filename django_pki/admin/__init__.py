from django.contrib import admin

from ..models import PrivateKey

from .private_key_admin import PrivateKeyAdmin

# Register your models here.
admin.site.register(PrivateKey, PrivateKeyAdmin)
