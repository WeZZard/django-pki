from typing import List

from cryptography.hazmat.primitives import serialization

from enumfields import Enum


class PrivateFormat(Enum):
    PKCS8 = "PKCS8"
    TRADITIONAL_OPEN_SSL = "TRADITIONAL_OPEN_SSL"

    def get_serialization_object(self) -> serialization.PrivateFormat:
        if self == PrivateFormat.PKCS8:
            return serialization.PrivateFormat.PKCS8
        if self == PrivateFormat.TRADITIONAL_OPEN_SSL:
            return serialization.PrivateFormat.TraditionalOpenSSL
        raise ValueError('Unexpected private format: {f}.'.format(f=self))

    @classmethod
    def get_available_private_formats(cls) -> List['PrivateFormat']:
        ret_val: List['PrivateFormat'] = [
            cls.PKCS8,
            cls.TRADITIONAL_OPEN_SSL,
        ]
        return ret_val

    class Labels:
        PKCS8 = "PKCS#8"
        TRADITIONAL_OPEN_SSL = "Traditional OpenSSL"
