from enumfields import Enum


class HashAlgorithm(Enum):
    SHA1 = 'SHA1'
    SHA224 = 'SHA224'
    SHA256 = 'SHA256'
    SHA384 = 'SHA384'
    SHA512 = 'SHA512'
    MD5 = 'MD5'
    BLAKE2_B = 'BLAKE2_B'
    BLAKE2_S = 'BLAKE2_S'

    class Label:
        SHA1 = 'SHA-1'
        SHA224 = 'SHA-224'
        SHA256 = 'SHA-256'
        SHA384 = 'SHA-384'
        SHA512 = 'SHA-512'
        MD5 = 'MD5'
        BLAKE2_B = 'BLAKE2b'
        BLAKE2_S = 'BLAKE2s'
    pass
