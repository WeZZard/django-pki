from django.contrib import admin

from ..models import PrivateKey
from ..models import PublicKey

from .private_key_admin import PrivateKeyAdmin
from .public_key_admin import PublicKeyAdmin

# Register your models here.
admin.site.register(PrivateKey, PrivateKeyAdmin)
admin.site.register(PublicKey, PublicKeyAdmin)
