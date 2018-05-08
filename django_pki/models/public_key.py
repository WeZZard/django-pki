from typing import Optional
from typing import Any

from django.db.models import Model
from django.db.models import ForeignKey
from django.db.models import CASCADE
from django.db.models import SET
from django.db.models import SET_NULL
from django.db.models import SET_DEFAULT
from django.db.models import PROTECT
from django.db.models.fields import CharField
from django.db.models.fields import BooleanField
from django.db.models.fields import BinaryField
from django.core.exceptions import ValidationError

from enumfields import EnumField

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_private_key

from ..common import EncryptionSchema
from ..common import PrivateKeySize
from ..common import EllipticCurve
from ..common import PrivateFormat
from ..common import Encoding

from ..models import PrivateKey


class PublicKey(Model):
    private_key: ForeignKey = ForeignKey(
        to=PrivateKey,
        related_name='public_key',
        on_delete=CASCADE, 
        null=False
    )
    
    def key_name(self) -> str:
        return self.private_key.name
    
    key_name.short_description = 'Name'
    key_name.help_text = 'The public key\'s name (The same to the paired ' \
                         'private key).'

    def encryption_schema(self) -> EncryptionSchema:
        private_key: PrivateKey = self.private_key
        encryption_schema: EncryptionSchema = private_key.encryption_schema
        return encryption_schema

    def key_size(self) -> PrivateKeySize:
        private_key: PrivateKey = self.private_key
        key_size: PrivateKeySize = private_key.key_size
        return key_size

    def elliptic_curve(self) -> EllipticCurve:
        private_key: PrivateKey = self.private_key
        elliptic_curve: EllipticCurve = private_key.elliptic_curve
        return elliptic_curve

    def encoding(self) -> Encoding:
        private_key: PrivateKey = self.private_key
        encoding: Encoding = private_key.encoding
        return encoding

    def format(self) -> PrivateFormat:
        private_key: PrivateKey = self.private_key
        key_format: PrivateFormat = private_key.format
        return key_format

    def is_encrypted(self) -> bool:
        private_key: PrivateKey = self.private_key
        is_encrypted: bool = private_key.is_encrypted
        return is_encrypted
    is_encrypted.boolean = True

    def encryption_schema_details(self) -> str:
        private_key: PrivateKey = self.private_key
        details: str = private_key.encryption_schema_details()
        return details

    key_bytes: BinaryField = BinaryField()

    pass
