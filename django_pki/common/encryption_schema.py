from typing import List

from enumfields import Enum


class EncryptionSchema(Enum):
    RSA = 'RSA'
    DSA = 'DSA'
    EC = 'EC'

    @classmethod
    def get_available_encryption_schemas(cls) -> List['EncryptionSchema']:
        ret_val: List['EncryptionSchema'] = [cls.RSA, cls.DSA, cls.EC]
        return ret_val
