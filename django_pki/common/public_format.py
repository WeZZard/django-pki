from typing import List

from cryptography.hazmat.primitives import serialization

from enumfields import Enum


class PublicFormat(Enum):
    SUBJECT_PUBLIC_KEY_INFO = "SUBJECT_PUBLIC_KEY_INFO"
    PKCS1 = "PKCS1"
    OPEN_SSH = "OPEN_SSH"

    def get_serialization_object(self) -> serialization.PublicFormat:
        if self == PublicFormat.SUBJECT_PUBLIC_KEY_INFO:
            return serialization.PublicFormat.SubjectPublicKeyInfo
        if self == PublicFormat.PKCS1:
            return serialization.PublicFormat.PKCS1
        if self == PublicFormat.OPEN_SSH:
            return serialization.PublicFormat.OpenSSH
        raise ValueError('Unexpected public format: {f}.'.format(f=self))

    @classmethod
    def get_available_public_formats(cls) -> List['PublicFormat']:
        ret_val: List['PublicFormat'] = [
            cls.SUBJECT_PUBLIC_KEY_INFO,
            cls.PKCS1,
            cls.OPEN_SSH
        ]
        return ret_val

    class Labels:
        SUBJECT_PUBLIC_KEY_INFO = "X.509 subjectPublicKeyInfo with PKCS#1"
        PKCS1 = "Raw PKCS#1"
        OPEN_SSH = "Open SSH"
