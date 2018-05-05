from typing import List

from cryptography.hazmat.primitives import serialization

from enumfields import Enum


class Encoding(Enum):
    PEM = "PEM"
    DER = "DER"
    OpenSSH = "OpenSSH"

    def get_serialization_object(self) -> serialization.Encoding:
        if self == Encoding.PEM:
            return serialization.Encoding.PEM
        if self == Encoding.DER:
            return serialization.Encoding.DER
        if self == Encoding.OpenSSH:
            return serialization.Encoding.OpenSSH
        raise ValueError('Unexpected encoding: {e}.'.format(e=self))

    @classmethod
    def get_available_encodings(cls) -> List['Encoding']:
        ret_val: List['Encoding'] = [cls.PEM, cls.DER, cls.OpenSSH]
        return ret_val
