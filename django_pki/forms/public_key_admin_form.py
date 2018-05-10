from typing import Set
from typing import Dict
from typing import Any
from typing import Optional
from typing import Iterable

from django.forms import ModelForm
from django.forms import ModelChoiceField
from django.forms.fields import CharField
from django.forms.widgets import PasswordInput

from enumfields import EnumField

from ..models import PublicKey
from ..models import PrivateKey
from ..common import Encoding
from ..common import PublicFormat


class PublicKeyAdminForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_newly_created = kwargs.get('instance') is None

    private_key = ModelChoiceField(
        label='Private Key',
        queryset=PrivateKey.objects.all().filter(public_key__isnull=True),
        required=False
    )

    passphrase = CharField(
        widget=PasswordInput,
        required=False,
        label='Passphrase',
        help_text='Type the passphrase if the private key is encrypted.',
    )

    encoding: EnumField = EnumField(
        Encoding,
        max_length=1,
        verbose_name='Encoding',
        choices=Encoding.get_available_public_key_encoding_choices(),
        default=Encoding.PEM,
        help_text='The public key encoding.',
    ).formfield()

    format: EnumField = EnumField(
        PublicFormat,
        max_length=1,
        default=PublicFormat.SUBJECT_PUBLIC_KEY_INFO,
        verbose_name='Format',
        help_text='The public key format.',
    ).formfield()

    def clean(self) -> Dict[str, str]:
        data = super().clean()

        private_key = self._validate_private_key_with_data(data=data)

        if private_key is not None:
            self._validate_private_key_passphrase_with_data(
                private_key=private_key,
                data=data
            )

            if self._is_newly_created or self._has_changed_items(
                self._key_bytes_dependent_data
            ):
                passphrase: str = data.get('passphrase')
                encoding = data.get('encoding')
                key_format = data.get('format')

                try:
                    key_bytes = private_key.to_primitive_public_key_bytes(
                        encoding=encoding,
                        key_format=key_format,
                        password=passphrase
                    )

                    data['_key_bytes'] = key_bytes
                except Exception as error:
                    self.add_error(field=None, error=error)

        return data

    def save(self, commit=True) -> PublicKey:
        private_key: PrivateKey = self.instance

        key_bytes = self.cleaned_data.get('_key_bytes')

        if key_bytes is not None:
            private_key.key_bytes = key_bytes

        return super().save(commit=commit)

    # Helpers

    def _has_changed_items(self, items: Iterable[str]) -> bool:
        return len(set(self.changed_data).intersection(set(items))) > 0

    # Validations

    def _validate_private_key_with_data(
            self,
            data: Dict[str, Any]
    ) -> Optional[PrivateKey]:
        if self._is_newly_created:
            private_key: Optional[PrivateKey] = data.get('private_key')
            if private_key is None:
                self.add_error(
                    field='private_key',
                    error='Private key is required.'
                )
                return None
            else:
                if hasattr(private_key, 'public_key'):
                    self.add_error(
                        field='private_key',
                        error='Private key has already got a paired public key.'
                    )
                return private_key
        else:
            private_key: PrivateKey = self.instance.private_key
            return private_key

    def _validate_private_key_passphrase_with_data(
            self,
            private_key: PrivateKey,
            data: Dict[str, Any]
    ):
        passphrase = data.get('passphrase')
        if not private_key.is_passphrase_valid(passphrase=passphrase):
            self.add_error(
                field='passphrase',
                error='Incorrect passphrase.'
            )

    _is_newly_created: bool

    _key_bytes_dependent_data: Set[str] = {
        'encryption_schema',
        'key_size',
        'elliptic_curve',
        'encoding',
        'format'
    }

    class Meta:
        model = PublicKey
        exclude = ['key_bytes']
