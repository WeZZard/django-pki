from typing import Dict
from typing import Set
from typing import Optional

from django.forms import ModelForm
from django.forms.fields import CharField
from django.forms.widgets import PasswordInput
from django.core.validators import EmailValidator

from enumfields import EnumField

from ..models import PrivateKey
from ..common import EncryptionSchema
from ..common import EllipticCurve
from ..common import Encoding
from ..common import PrivateFormat
from ..common import PrivateKeySize


class PrivateKeyAdminForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_newly_created = kwargs.get('instance') is None

    key_name = CharField(
        help_text=
        'The name of the private key. Format: "service@hostname.domain".',
        validators=[EmailValidator()]
    )

    encryption_schema = EnumField(
        EncryptionSchema,
        max_length=1,
        default=EncryptionSchema.EC,
        verbose_name='Encryption Schema',
        help_text='The private key encryption schema.',
    ).formfield()

    key_size: EnumField = EnumField(
        PrivateKeySize,
        max_length=1,
        null=True,
        blank=True,
        verbose_name='Private Key Size',
        help_text='The private key size.',
    ).formfield()

    elliptic_curve: EnumField = EnumField(
        EllipticCurve,
        max_length=1,
        null=True,
        blank=True,
        choices=EllipticCurve.get_available_elliptic_curve_choices(),
        default=EllipticCurve.SECP521R1,
        verbose_name='Elliptic Curve',
        help_text='The elliptic curve.',
    ).formfield()

    encoding: EnumField = EnumField(
        Encoding,
        max_length=1,
        verbose_name='Encoding',
        choices=Encoding.get_available_private_key_encoding_choices(),
        default=Encoding.PEM,
        help_text='The private key encoding.',
    ).formfield()

    format: EnumField = EnumField(
        PrivateFormat,
        max_length=1,
        default=PrivateFormat.PKCS8,
        verbose_name='Format',
        help_text='The private key format.',
    ).formfield()

    old_passphrase = CharField(
        widget=PasswordInput,
        required=False,
        label='Old Passphrase',
        help_text='Type the old passphrase.',
    )

    passphrase = CharField(
        widget=PasswordInput,
        required=False,
        label='Passphrase',
        help_text='Type the passphrase.',
    )

    redundant_passphrase = CharField(
        widget=PasswordInput,
        required=False,
        label='Passphrase Again',
        help_text='Type the passphrase again.',
    )

    def clean(self) -> Dict[str, str]:
        data = super().clean()

        private_key: PrivateKey = self.instance

        # Validate old passphrase
        is_old_passphrase_valid = self._validate_old_passphrase_is_valid(
            private_key=private_key,
            data=data
        )

        # Validate passphrase
        is_passphrase_ensured = self._validate_passphrase_ensured(data=data)

        if is_old_passphrase_valid and is_passphrase_ensured:
            if self._is_newly_created or self._needs_update_derived_data:

                encryption_schema = data.get('encryption_schema')
                key_size = data.get('key_size')
                elliptic_curve = data.get('elliptic_curve')
                key_encoding = data.get('encoding')
                key_format = data.get('format')
                passphrase = data.get('passphrase')

                try:
                    key_bytes: bytes = PrivateKey.make_key_bytes(
                        encryption_schema=encryption_schema,
                        key_size=key_size,
                        elliptic_curve=elliptic_curve,
                        encoding=key_encoding,
                        key_format=key_format,
                        passphrase=passphrase
                    )

                    is_encrypted = len(passphrase) > 0

                    data['_key_bytes'] = key_bytes
                    data['_is_encrypted'] = is_encrypted
                except Exception as error:
                    self.add_error(field=None, error=error)

            else:
                old_passphrase = data.get('old_passphrase')
                passphrase = data.get('passphrase')

                if self._needs_re_encrypt_key_bytes(
                        old_passphrase=old_passphrase,
                        new_passphrase=passphrase
                ):
                    try:
                        key_bytes = private_key.to_primitive_private_key_bytes(
                            old_passphrase,
                            passphrase
                        )

                        is_encrypted = len(passphrase) > 0

                        data['_key_bytes'] = key_bytes
                        data['_is_encrypted'] = is_encrypted
                    except Exception as error:
                        self.add_error(field=None, error=error)

        return data

    def save(self, commit=True) -> PrivateKey:
        private_key: PrivateKey = self.instance

        key_bytes: Optional[bytes] = self.cleaned_data.get('_key_bytes')
        is_encrypted: Optional[bool] = self.cleaned_data.get('_is_encrypted')

        if key_bytes is not None:
            private_key.key_bytes = key_bytes

        if is_encrypted is not None:
            private_key.is_encrypted = is_encrypted

        return super().save(commit=commit)

    @property
    def _needs_update_derived_data(self) -> bool:
        return len(
            set(self.changed_data).intersection(
                set(self._derived_data_dependent_data)
            )
        ) > 0

    @staticmethod
    def _needs_re_encrypt_key_bytes(
            old_passphrase: Optional[str],
            new_passphrase: Optional[str]
    ) -> bool:
        return old_passphrase != new_passphrase

    _is_newly_created: bool

    _derived_data_dependent_data: Set[str] = {
        'encryption_schema',
        'key_size',
        'elliptic_curve',
        'encoding',
        'format'
    }

    # Validations

    def _validate_old_passphrase_is_valid(
            self,
            private_key: PrivateKey,
            data: Dict[str, str]
    ) -> bool:
        old_passphrase = data.get('old_passphrase')
        if self._is_newly_created:
            if len(old_passphrase) > 0:
                self.add_error(
                    field='old_passphrase',
                    error='Old passphrase is unnecessary for newly'
                          ' created private key.'
                )
            return True
        else:
            (is_passphrase_valid, error) = private_key.is_passphrase_valid(
                old_passphrase
            )
            if not is_passphrase_valid:
                self.add_error(
                    field='old_passphrase',
                    error='Incorrect old passphrase: %s' % error
                )
                return False
            else:
                return True

    def _validate_passphrase_ensured(self, data: Dict[str, str]) -> bool:
        passphrase = data.get('passphrase')
        redundant_passphrase = data.get('redundant_passphrase')

        if passphrase != redundant_passphrase:
            self.add_error(
                field='redundant_passphrase',
                error='Two passphrases shall be the same.'
            )
            return False
        else:
            return True

    class Meta:
        model = PrivateKey
        exclude = ['key_bytes', 'is_encrypted']
