from django.contrib.admin import ModelAdmin

from ..forms import PublicKeyAdminForm
from ..models import PublicKey


class PublicKeyAdmin(ModelAdmin):
    list_display = (
        'key_name',
        'encryption_schema',
        'encryption_schema_details',
        'encoding',
        'format',
        'is_encrypted',
    )

    def get_fields(self, request, obj: PublicKey=None):
        if obj:
            return ('key_name', 'private_key') \
                + self._private_key_derived_fields
        else:
            return 'private_key',

    def get_readonly_fields(self, request, obj: PublicKey=None):
        if obj:
            return self.get_fields(request=request, obj=obj)
        else:
            return ()

    _private_key_derived_fields = (
        'encryption_schema',
        'key_size',
        'elliptic_curve',
        'encoding',
        'format',
        'is_encrypted',
    )
