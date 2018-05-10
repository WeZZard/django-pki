from typing import Optional
from typing import Any

from django.db.models import Model
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


class PrivateKey(Model):
    # Fields
    key_name: CharField = CharField(
        unique=True,
        name='key_name',
        max_length=256,
        verbose_name='Name',
        help_text='The name to identify the private key.',
    )

    encryption_schema: EnumField = EnumField(
        EncryptionSchema,
        name='encryption_schema',
        max_length=1,
        default=EncryptionSchema.EC,
        verbose_name='Encryption Schema',
        help_text='The private key encryption schema.',
    )

    key_size: EnumField = EnumField(
        PrivateKeySize,
        name='key_size',
        max_length=1,
        null=True,
        blank=True,
        verbose_name='Private Key Size',
        help_text='The private key size.',
    )

    elliptic_curve: EnumField = EnumField(
        EllipticCurve,
        name='elliptic_curve',
        max_length=1,
        null=True,
        blank=True,
        default=EllipticCurve.SECP521R1,
        verbose_name='Elliptic Curve',
        help_text='The elliptic curve.',
    )

    encoding: EnumField = EnumField(
        Encoding,
        name='encoding',
        max_length=1,
        verbose_name='Encoding',
        default=Encoding.PEM,
        help_text='The private key encoding.',
    )

    format: EnumField = EnumField(
        PrivateFormat,
        name='format',
        max_length=1,
        default=PrivateFormat.PKCS8,
        verbose_name='Format',
        help_text='The private key format.',
    )

    is_encrypted: BooleanField = BooleanField(
        name='is_encrypted',
        max_length=1,
        blank=True,
        default=False,
        verbose_name='Encrypted',
        help_text='Is the private key encrypted (typically by a passphrase)?',
    )

    is_encrypted.boolean = True

    key_bytes: BinaryField = BinaryField(
        name='key_bytes',
        blank=True, 
        null=True,
        verbose_name='Key Bytes',
        help_text='Binary representation of the private key.',
    )

    def has_paired_public_key(self) -> bool:
        return hasattr(self, 'public_key')

    has_paired_public_key.boolean = True
    has_paired_public_key.short_description = 'Has Paired Public Key'

    # List Fields
    def encryption_schema_details(self) -> str:
        encryption_schema = self.encryption_schema

        if encryption_schema == EncryptionSchema.RSA:
            key_size: PrivateKeySize = self.key_size
            return key_size.__str__()
        elif encryption_schema == EncryptionSchema.DSA:
            key_size: PrivateKeySize = self.key_size
            return key_size
        elif encryption_schema == EncryptionSchema.EC:
            elliptic_curve: EllipticCurve = self.elliptic_curve
            return elliptic_curve.__str__()
        else:
            raise ValidationError(
                'Invalid encryption schema: %s.' % encryption_schema.name
            )

    # Helper
    def is_passphrase_valid(
            self,
            passphrase: Optional[str]
    ) -> (bool, Optional[Exception]):
        assert passphrase is None or isinstance(passphrase, str)
        passphrase_bytes = None if passphrase is None \
            else passphrase.encode('utf-8')

        try:
            _ = self.to_primitive_private_key(password=passphrase_bytes)
        except Exception as error:
            return False, error
        finally:
            return True, None

    # Getting Primitive Public Key

    def to_primitive_public_key(self, password: Optional[str]) -> Any:
        primitive_private_key = self.to_primitive_private_key(password)
        return primitive_private_key.public_key()

    def to_primitive_public_key_bytes(
            self,
            encoding: Encoding,
            key_format: PrivateFormat,
            password: Optional[str]
    ) -> bytes:
        public_key = self.to_primitive_public_key(password=password)
        return public_key.public_bytes(
            encoding=encoding.get_serialization_object(),
            format=key_format.get_serialization_object()
        )

    # Getting Primitive Private Key

    def to_primitive_private_key(self, password: Optional[str]) -> Any:
        encoding: Encoding = self.encoding
        key_bytes: bytes = self.key_bytes
        return self.get_primitive_private_key(
            encoding=encoding,
            data=key_bytes,
            decrypt_password=password
        )

    def to_primitive_private_key_bytes(
            self,
            decrypt_password: Optional[str],
            encrypt_password: Optional[str]
    ) -> bytes:
        private_key = self.to_primitive_private_key(password=decrypt_password)
        encoding: Encoding = self.encoding
        key_format: PrivateFormat = self.format
        encryption_algorithm = self._get_encryption_algorithm(
            passphrase=encrypt_password
        )
        return private_key.private_bytes(
            encoding=encoding.get_serialization_object(),
            format=key_format.get_serialization_object(),
            encryption_algorithm=encryption_algorithm
        )

    # Validation

    def clean(self):
        encryption_schema = self.encryption_schema
        key_size = self.key_size
        elliptic_curve = self.elliptic_curve

        if encryption_schema == EncryptionSchema.RSA:
            assert isinstance(key_size, PrivateKeySize)
            if elliptic_curve is not None:
                raise ValidationError(
                    "Elliptic curve is unnecessary for encryption schema: %s."
                    % encryption_schema.name
                )
        elif encryption_schema == EncryptionSchema.DSA:
            assert isinstance(key_size, PrivateKeySize)
            if elliptic_curve is not None:
                raise ValidationError(
                    "Elliptic curve is unnecessary for encryption schema: %s."
                    % encryption_schema.name
                )
        elif encryption_schema == EncryptionSchema.EC:
            if key_size is not None:
                raise ValidationError(
                    "Private key size is unnecessary for encryption schema: %s."
                    % encryption_schema.name
                )
            assert isinstance(elliptic_curve, EllipticCurve)
        else:
            raise ValidationError(
                'Invalid encryption schema: %s.' % encryption_schema.name
            )

    # Factory

    @classmethod
    def make(
            cls,
            name: str,
            encryption_schema: EncryptionSchema,
            key_size: Optional[PrivateKeySize],
            elliptic_curve: Optional[EllipticCurve],
            key_encoding: Encoding,
            key_format: PrivateFormat,
            passphrase: Optional[str],
    ) -> 'PrivateKey':
        private_key = cls()

        assert isinstance(name, str)
        assert isinstance(encryption_schema, EncryptionSchema)
        assert key_size is None or isinstance(key_size, PrivateKeySize)
        assert elliptic_curve is None \
            or isinstance(elliptic_curve, EllipticCurve)
        assert isinstance(key_encoding, Encoding)
        assert isinstance(key_format, PrivateFormat)
        assert passphrase is None or isinstance(passphrase, str)

        private_key.key_name = name
        private_key.encryption_schema = encryption_schema
        private_key.key_size = key_size
        private_key.elliptic_curve = elliptic_curve
        private_key.encoding = key_encoding
        private_key.format = key_format
        private_key.passphrase = passphrase

        private_key.update_derived_data(
            encryption_schema=encryption_schema,
            key_size=key_size,
            elliptic_curve=elliptic_curve,
            encoding=key_encoding,
            key_format=key_format,
            new_passphrase=passphrase,
        )
        
        return private_key

    # Utilities

    @staticmethod
    def get_primitive_private_key(
            encoding: Encoding,
            data: bytes,
            decrypt_password: Optional[str]
    ) -> Any:
        assert isinstance(encoding, Encoding)
        assert isinstance(data, bytes)
        assert decrypt_password is None or isinstance(decrypt_password, str)

        password: bytes = None \
            if decrypt_password is None or len(decrypt_password) == 0 \
            else decrypt_password.encode('utf-8')

        backend = default_backend()
        if encoding == Encoding.DER:
            return load_der_private_key(data, password, backend)
        if encoding == Encoding.PEM:
            key = load_pem_private_key(data, password, backend)
            return key
        if encoding == Encoding.OPEN_SSH:
            assert NotImplementedError(
                'Loading private key which encoded with Open SSH is not \
supported now.'
            )

    @classmethod
    def make_key_bytes(
            cls,
            encryption_schema: EncryptionSchema,
            key_size: Optional[PrivateKeySize],
            elliptic_curve: Optional[EllipticCurve],
            encoding: Encoding,
            key_format: PrivateFormat,
            passphrase: Optional[str],
    ) -> bytes:
        assert isinstance(encryption_schema, EncryptionSchema)
        assert isinstance(encoding, Encoding)
        assert isinstance(key_format, PrivateFormat)
        assert passphrase is None or isinstance(passphrase, str)

        if encryption_schema == EncryptionSchema.RSA:
            assert isinstance(key_size, PrivateKeySize)
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size.to_int(),
                backend=default_backend()
            )
        elif encryption_schema == EncryptionSchema.DSA:
            assert isinstance(key_size, PrivateKeySize)
            key = dsa.generate_private_key(
                key_size=key_size.to_int(),
                backend=default_backend()
            )
        elif encryption_schema == EncryptionSchema.EC:
            assert isinstance(elliptic_curve, EllipticCurve)
            key = ec.generate_private_key(
                curve=elliptic_curve.get_oid_type()(),
                backend=default_backend()
            )
        else:
            raise ValueError(
                'Unexpected encryption schema: {schema}.'.format(
                    schema=encryption_schema
                )
            )

        key_bytes: bytes = key.private_bytes(
            encoding=encoding.get_serialization_object(),
            format=key_format.get_serialization_object(),
            encryption_algorithm=cls._get_encryption_algorithm(passphrase),
        )

        return key_bytes

    @staticmethod
    def _get_encryption_algorithm(passphrase: Optional[str]) -> object:
        if passphrase is None:
            return NoEncryption()
        elif len(passphrase) == 0:
            return NoEncryption()
        elif isinstance(passphrase, str):
            passphrase_bytes = passphrase.encode('utf-8')
            return BestAvailableEncryption(password=passphrase_bytes)
        else:
            raise ValueError(
                'Invalid passphrase. "{p}" shall be ``None`` or type of \
``str``.'.format(p=passphrase)
            )

    def __str__(self) -> str:
        name: str = self.key_name
        return name
