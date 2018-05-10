from django.db.models import Model
from django.db.models import OneToOneField
from django.db.models import CASCADE
from django.db.models.fields import BinaryField

from enumfields import EnumField

from ..common import Encoding
from ..common import PublicFormat

from ..models import PrivateKey


class PublicKey(Model):
    private_key: OneToOneField = OneToOneField(
        to=PrivateKey,
        related_name='public_key',
        on_delete=CASCADE,
    )
    
    def key_name(self) -> str:
        private_key: PrivateKey = self.private_key
        name: str = private_key.key_name
        return name
    
    key_name.short_description = 'Name'
    key_name.help_text = 'The public key\'s name (The same to the paired ' \
                         'private key).'

    def private_key_encryption_schema(self) -> str:
        private_key: PrivateKey = self.private_key
        return private_key.encryption_schema.__str__()

    private_key_encryption_schema.short_description = \
        'Private Key Encryption Schema'

    def private_key_size(self) -> str:
        private_key: PrivateKey = self.private_key
        if private_key.key_size is None:
            return '------'
        else:
            return private_key.key_size.__str__()

    private_key_size.short_description = 'Private Key Size'

    def private_key_elliptic_curve(self) -> str:
        private_key: PrivateKey = self.private_key
        if private_key.elliptic_curve is None:
            return '------'
        else:
            return private_key.elliptic_curve.__str__()

    private_key_elliptic_curve.short_description = 'Private Key Elliptic Curve'

    encoding: EnumField = EnumField(
        Encoding,
        max_length=1,
        verbose_name='Encoding',
        default=Encoding.PEM,
        help_text='The public key encoding.',
    )

    format: EnumField = EnumField(
        PublicFormat,
        max_length=1,
        default=PublicFormat.PKCS1,
        verbose_name='Format',
        help_text='The public key format.',
    )

    key_bytes: BinaryField = BinaryField()

    def __str__(self) -> str:
        return self.key_name()

    pass
