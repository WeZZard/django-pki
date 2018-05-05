from typing import List

from cryptography.hazmat.primitives import serialization

from enumfields import Enum


class PrivateFormat(Enum):
    PKCS8 = "PKCS8"
    TraditionalOpenSSL = "TraditionalOpenSSL"

    def get_serialization_object(self) -> serialization.PrivateFormat:
        if self == PrivateFormat.PKCS8:
            return serialization.PrivateFormat.PKCS8
        if self == PrivateFormat.TraditionalOpenSSL:
            return serialization.PrivateFormat.TraditionalOpenSSL
        raise ValueError('Unexpected private format: {f}.'.format(f=self))

    @classmethod
    def get_available_private_formats(cls) -> List['PrivateFormat']:
        ret_val: List['PrivateFormat'] = [
            cls.PKCS8,
            cls.TraditionalOpenSSL
        ]
        return ret_val
