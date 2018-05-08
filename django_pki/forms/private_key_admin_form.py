from typing import Dict
from typing import Set

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
    _is_newly_created: bool

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

        # Validate old passphrase
        self._validate_old_passphrase(data=data)

        # Validate passphrase
        self._validate_passphrase(data=data)

        return data

    def save(self, commit=True) -> PrivateKey:
        private_key: PrivateKey = self.instance

        old_passphrase = self['old_passphrase'].value()
        passphrase = self['passphrase'].value()
        redundant_passphrase = self['redundant_passphrase'].value()

        # Fetching data from stored private key
        encryption_schema: EncryptionSchema = private_key.encryption_schema
        key_size: PrivateKeySize = private_key.key_size
        elliptic_curve: EllipticCurve = private_key.elliptic_curve
        key_encoding: Encoding = private_key.encoding
        key_format: PrivateFormat = private_key.format

        # Data validity assertions
        assert (self._is_newly_created and old_passphrase is None) \
            or not self._is_newly_created
        assert passphrase == redundant_passphrase
        assert (key_size is None) is not (elliptic_curve is None)

        needs_update_derived_data = len(
            set(self.changed_data).intersection(
                self._derived_data_dependent_data
            )
        ) > 0

        if needs_update_derived_data or self._is_newly_created:
            private_key.update_derived_data(
                encryption_schema=encryption_schema,
                key_size=key_size,
                elliptic_curve=elliptic_curve,
                encoding=key_encoding,
                key_format=key_format,
                new_passphrase=passphrase
            )
        else:
            private_key.re_encrypt_key_bytes_if_needed(
                old_passphrase=old_passphrase,
                new_passphrase=passphrase
            )

        return super().save(commit=commit)

    _derived_data_dependent_data: Set[str] = {
        'encryption_schema',
        'key_size',
        'elliptic_curve',
        'encoding',
        'format'
    }

    # Validations

    def _validate_old_passphrase(self, data: Dict[str, str]):
        old_passphrase = data.get('old_passphrase')
        if self._is_newly_created:
            if len(old_passphrase) > 0:
                self.add_error(
                    field='old_passphrase',
                    error='Old passphrase is unavailable for newly'
                          ' created private key.'
                )
        else:
            private_key: PrivateKey = self.instance
            (is_passphrase_valid, error) = private_key.is_passphrase_valid(
                old_passphrase
            )
            if not is_passphrase_valid:
                self.add_error(
                    field='old_passphrase',
                    error='Incorrect old passphrase: %s' % error
                )

    def _validate_passphrase(self, data: Dict[str, str]):
        passphrase = data.get('passphrase')
        redundant_passphrase = data.get('redundant_passphrase')

        if passphrase != redundant_passphrase:
            self.add_error(
                field='redundant_passphrase',
                error='Two passphrases shall be the same.'
            )

    class Meta:
        model = PrivateKey
        exclude = ['key_bytes', 'is_encrypted']
