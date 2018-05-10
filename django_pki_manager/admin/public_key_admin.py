from django.contrib.admin import ModelAdmin

from ..forms import PublicKeyAdminForm
from ..models import PublicKey


class PublicKeyAdmin(ModelAdmin):
    form = PublicKeyAdminForm

    list_display = ('key_name', 'encoding', 'format',)

    def get_fields(self, request, obj: PublicKey=None):
        if obj:
            return ('key_name', 'passphrase') \
                + self._private_key_fields \
                + self._public_key_fields
        else:
            return ('private_key', 'passphrase') + self._public_key_fields

    def get_readonly_fields(self, request, obj: PublicKey=None):
        if obj:
            return ('key_name', ) + self._private_key_fields
        else:
            return ()

    _public_key_fields = ('encoding', 'format',)

    _private_key_fields = (
        'private_key_encryption_schema',
        'private_key_size',
        'private_key_elliptic_curve',
    )
