from typing import List

from enumfields import Enum


class PrivateKeySize(Enum):
    BIT_1024 = '1024 bit'
    BIT_2048 = '2048 bit'
    BIT_3072 = '3072 bit'
    BIT_4096 = '4096 bit'

    def to_int(self) -> int:
        if type(self).BIT_1024 == self:
            return 1024
        if type(self).BIT_2048 == self:
            return 2048
        if type(self).BIT_3072 == self:
            return 3072
        if type(self).BIT_4096 == self:
            return 4096
        raise ValueError('Unexpected private key size: {s}.'.format(s=self))

    @classmethod
    def get_available_private_key_sizes(cls) -> List['PrivateKeySize']:
        ret_val: List['PrivateKeySize'] = [
            cls.BIT_1024,
            cls.BIT_2048,
            cls.BIT_3072,
            cls.BIT_4096,
        ]
        return ret_val
