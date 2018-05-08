from typing import List
from typing import Iterable
from typing import Callable
from typing import Tuple
from typing import Optional
from typing import Any

from cryptography.hazmat.primitives import serialization

from enumfields import Enum


class Encoding(Enum):
    PEM = "PEM"
    DER = "DER"
    OPEN_SSH = "OPEN_SSH"

    def get_serialization_object(self) -> serialization.Encoding:
        if self == Encoding.PEM:
            return serialization.Encoding.PEM
        if self == Encoding.DER:
            return serialization.Encoding.DER
        if self == Encoding.OPEN_SSH:
            return serialization.Encoding.OpenSSH
        raise ValueError('Unexpected encoding: {e}.'.format(e=self))

    def get_private_key_serializer(
            self
    ) -> Optional[Callable[[Any, Any, Any], Any]]:
        if self == Encoding.PEM:
            return serialization.load_pem_private_key
        if self == Encoding.DER:
            return serialization.load_der_private_key
        return None

    def is_available_for_serializing_private_key(self) -> bool:
        return self.get_private_key_serializer() is not None

    @classmethod
    def get_all_encodings(cls) -> List['Encoding']:
        ret_val: List['Encoding'] = [cls.PEM, cls.DER, cls.OPEN_SSH]
        return ret_val

    @classmethod
    def get_available_private_key_encodings(cls) -> List['Encoding']:
        return list(filter(
            lambda x: x.is_available_for_serializing_private_key(),
            cls.get_all_encodings()
        ))

    @classmethod
    def get_available_private_key_encoding_choices(
            cls
    ) -> Iterable[Tuple[str, str]]:
        return [
            (each_encoding.value, each_encoding.label)
            for each_encoding in cls.get_available_private_key_encodings()
        ]

    class Labels:
        PEM = "PEM"
        DER = "DER"
        OPEN_SSH = "Open SSH"
