from typing import Dict
from typing import Optional

from django.db.models import Model
from django.forms import ModelForm
from django.forms import ModelChoiceField
from django.forms.fields import CharField
from django.forms.fields import ChoiceField
from django.forms.widgets import PasswordInput
from django.core.validators import EmailValidator

from enumfields import EnumField

from ..models import PublicKey
from ..models import PrivateKey
from ..common import EncryptionSchema
from ..common import EllipticCurve
from ..common import Encoding
from ..common import PrivateFormat
from ..common import PrivateKeySize


class PublicKeyAdminForm(ModelForm):
    _is_newly_created: bool

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_newly_created = kwargs.get('instance') is None

    private_key = ModelChoiceField(
        label='Private Key',
        queryset=PrivateKey.objects.all().filter(public_key=None)
    )

    def clean(self):
        instance = super().clean()
        if self['private_key'].has_paired_public_key:
            self.add_error(
                field='private_key',
                error='Private key has already got a paired public key.'
            )
        return instance
    
    def save(self, commit=True) -> PublicKey:
        return super().save(commit=commit)

    class Meta:
        model = PublicKey
        exclude = []
