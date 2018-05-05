from typing import Optional
from typing import Dict

from django.db.models import Model
from django.db.models.fields import CharField
from django.db.models.fields import TextField

from enumfields import EnumField

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

from ..common import EncryptionSchema
from ..common import PrivateKeySize
from ..common import EllipticCurve
from ..common import PrivateFormat
from ..common import Encoding


class PrivateKey(Model):
    def __init__(
            self, 
            name: str,
            encryption_schema: EncryptionSchema,
            key_size: Optional[PrivateKeySize],
            elliptic_curve: Optional[EllipticCurve],
            encoding: Encoding,
            private_format: PrivateFormat,
            passphrase: Optional[bytes],
            *args,
            **kwargs
    ):
        super().__init__(*args, **kwargs)
        assert isinstance(name, str)
        assert isinstance(encryption_schema, EncryptionSchema)
        assert key_size is None or isinstance(key_size, PrivateKeySize)
        assert elliptic_curve is None \
            or isinstance(elliptic_curve, EllipticCurve)
        assert isinstance(encoding, Encoding)
        assert isinstance(private_format, PrivateFormat)
        assert passphrase is None or isinstance(passphrase, bytes)

        self._name = name
        self._encryption_schema = encryption_schema
        self._key_size = key_size
        self._elliptic_curve = elliptic_curve
        self._encoding = encoding
        self._private_format = private_format
        self._passphrase = passphrase
        
        self._key_bytes = type(self)._get_key_bytes(
            encryption_schema,
            key_size,
            elliptic_curve,
            encoding,
            private_format,
            passphrase
        )
        
        # self._key_bytes['hidden'] = True

    # Fields
    _name: CharField = CharField(
        max_length=256,
        name='Name'
    )

    _encryption_schema: EnumField = EnumField(
        EncryptionSchema,
        max_length=1,
        name='Encryption Schema',
    )

    _key_size: EnumField = EnumField(
        PrivateKeySize,
        max_length=1,
        null=True,
        name='Private Key Size',
    )

    _elliptic_curve: EnumField = EnumField(
        EllipticCurve,
        max_length=1,
        null=True,
        name='Elliptic Curve',
    )

    _encoding: EnumField = EnumField(
        Encoding,
        max_length=1,
        name='Encoding',
    )

    _private_format: EnumField = EnumField(
        PrivateFormat,
        max_length=1,
        name='Private Format',
    )

    _passphrase: CharField = CharField(
        max_length=256,
        null=True,
        name='Passphrase',
    )

    _key_bytes: TextField = TextField()

    # Properties
    @property
    def name(self) -> str:
        assert isinstance(self._name, str)
        return self._name

    @name.setter
    def name(self, new_value: str):
        assert isinstance(new_value, str)
        self._name = new_value

    @property
    def encryption_schema(self) -> EncryptionSchema:
        assert isinstance(self._encryption_schema, EncryptionSchema)
        return self._encryption_schema

    @property
    def key_size(self) -> Optional[PrivateKeySize]:
        if self._key_size is None:
            return None
        assert isinstance(self._key_size, PrivateKeySize)
        return self._key_size

    @property
    def elliptic_curve(self) -> Optional[EllipticCurve]:
        if self._elliptic_curve is None:
            return None
        assert isinstance(self._elliptic_curve, EllipticCurve)
        return self._elliptic_curve

    @property
    def encoding(self) -> Encoding:
        assert isinstance(self._encoding, Encoding)
        return self._encoding

    @property
    def private_format(self) -> PrivateFormat:
        assert isinstance(self._private_format, PrivateFormat)
        return self._private_format

    @property
    def passphrase(self) -> Optional[bytes]:
        assert self._passphrase is None or isinstance(self._passphrase, bytes)
        return self._passphrase

    @property
    def key_bytes(self) -> str:
        assert isinstance(self._key_bytes, str)
        return self._key_bytes

    # Validation

    def clean(self) -> Dict:
        cleaned_data = super().clean()

        encryption_schema = cleaned_data['_encryption_schema']
        key_size = cleaned_data.get('_key_size')
        elliptic_curve = cleaned_data.get('_elliptic_curve')

        if encryption_schema == EncryptionSchema.RSA:
            assert isinstance(key_size, PrivateKeySize)
            assert elliptic_curve is None
        elif encryption_schema == EncryptionSchema.DSA:
            assert isinstance(key_size, PrivateKeySize)
            assert elliptic_curve is None
        elif encryption_schema == EncryptionSchema.EC:
            assert key_size is None
            assert isinstance(elliptic_curve, EllipticCurve)
        else:
            raise ValueError(
                'Invalid encryption schema: {s}.'.format(s=encryption_schema)
            )

        return cleaned_data

    # Factory

    @classmethod
    def make(
            cls,
            name: str,
            encryption_schema: EncryptionSchema,
            key_size: Optional[PrivateKeySize],
            elliptic_curve: Optional[EllipticCurve],
            encoding: Encoding,
            private_format: PrivateFormat,
            passphrase: Optional[bytes],
    ) -> 'PrivateKey':
        return cls(
            name,
            encryption_schema,
            key_size,
            elliptic_curve,
            encoding,
            private_format,
            passphrase
        )

    # Utilities

    @classmethod
    def _get_key_bytes(
            cls,
            encryption_schema: EncryptionSchema,
            key_size: Optional[PrivateKeySize],
            elliptic_curve: Optional[EllipticCurve],
            encoding: Encoding,
            private_format: PrivateFormat,
            passphrase: Optional[bytes],
    ) -> str:
        assert isinstance(encryption_schema, EncryptionSchema)
        assert isinstance(encoding, Encoding)
        assert isinstance(private_format, PrivateFormat)
        assert passphrase is None or isinstance(passphrase, bytes)

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
                'Invalid encryption schema: {s}.'.format(s=encryption_schema)
            )

        key_bytes = key.private_bytes(
            encoding=encoding.get_serialization_object(),
            format=private_format.get_serialization_object(),
            encryption_algorithm=cls._get_encryption_algorithm(passphrase),
        )

        return key_bytes

    @staticmethod
    def _get_encryption_algorithm(
            passphrase: Optional[bytes]
    ) -> object:
        if passphrase is None:
            return NoEncryption()
        if isinstance(passphrase, bytes):
            if len(passphrase) == 0:
                return NoEncryption()
            else:
                return BestAvailableEncryption(password=passphrase)
        raise ValueError(
            'Invalid passphrase. "{p}" shall be ``None`` or type of ``bytes``.'
            .format(p=passphrase)
        )

