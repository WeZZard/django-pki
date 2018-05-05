from typing import List

from cryptography.hazmat.primitives import serialization

from enumfields import Enum


class PublicFormat(Enum):
    SubjectPublicKeyInfo = "X.509 subjectPublicKeyInfo with PKCS#1"
    PKCS1 = "Raw PKCS#1"
    OpenSSH = "OpenSSH"

    def get_serialization_object(self) -> serialization.PublicFormat:
        if self == PublicFormat.SubjectPublicKeyInfo:
            return serialization.PublicFormat.SubjectPublicKeyInfo
        if self == PublicFormat.PKCS1:
            return serialization.PublicFormat.PKCS1
        if self == PublicFormat.OpenSSH:
            return serialization.PublicFormat.OpenSSH
        raise ValueError('Unexpected public format: {f}.'.format(f=self))

    @classmethod
    def get_available_public_formats(cls) -> List['PublicFormat']:
        ret_val: List['PublicFormat'] = [
            cls.SubjectPublicKeyInfo,
            cls.PKCS1,
            cls.OpenSSH
        ]
        return ret_val
