from django.contrib.admin import ModelAdmin

from ..forms import PrivateKeyAdminForm
from ..models import PrivateKey


class PrivateKeyAdmin(ModelAdmin):
    form = PrivateKeyAdminForm

    list_display = (
        'key_name',
        'encryption_schema',
        'encryption_schema_details',
        'encoding',
        'format',
        'is_encrypted',
        'has_paired_public_key'
    )

    def get_fields(self, request, obj: PrivateKey=None):
        if obj:
            return ('key_name',) \
                   + self._private_key_required_fields \
                   + (
                       'is_encrypted',
                       'has_paired_public_key',
                       'old_passphrase'
                   ) \
                   + self._passphrase_fields
        return ('key_name',) \
            + self._private_key_required_fields \
            + self._passphrase_fields

    def get_readonly_fields(self, request, obj: PrivateKey=None):
        if obj:  # editing an existing object
            if obj.has_paired_public_key():
                return self._private_key_required_fields \
                       + ('is_encrypted', 'has_paired_public_key')
            else:
                return 'is_encrypted', 'has_paired_public_key'
        return ()

    _private_key_required_fields = (
        'encryption_schema',
        'key_size',
        'elliptic_curve',
        'encoding',
        'format',
    )

    _passphrase_fields = ('passphrase', 'redundant_passphrase',)
