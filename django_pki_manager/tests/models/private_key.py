from typing import List
from typing import Tuple
from typing import Optional

from django.test import TestCase

from ...common import EncryptionSchema
from ...common import PrivateKeySize
from ...common import EllipticCurve
from ...common import PrivateFormat
from ...common import Encoding

from ...models import PrivateKey

from itertools import product


class PrivateKeyTest(TestCase):
    def test_creating_private_key(self):
        self.maxDiff = None

        passphrases = [None, 'password']

        available_private_key_sizes: List[Optional[PrivateKeySize]] = \
            PrivateKeySize.get_available_private_key_sizes()
        available_private_key_sizes.append(None)

        available_elliptic_curves: List[Optional[EllipticCurve]] = \
            EllipticCurve.get_available_elliptic_curves()
        available_elliptic_curves.append(None)

        combinations = list(
            product(
                EncryptionSchema.get_available_encryption_schemas(),
                available_private_key_sizes,
                available_elliptic_curves,
                PrivateFormat.get_available_private_formats(),
                Encoding.get_available_private_key_encodings(),
                passphrases,
            )
        )

        for each_combination in filter(
                type(self).is_valid_init_combination,
                combinations
        ):
            (
                schema,
                key_size,
                curve_name,
                raw_format,
                raw_encoding,
                passphrase
            ) = each_combination

            print(each_combination)

            key_format: PrivateFormat = raw_format

            key_encoding: Encoding = raw_encoding

            private_key = PrivateKey.make(
                name='Test',
                encryption_schema=schema,
                key_size=key_size,
                elliptic_curve=curve_name,
                key_encoding=key_encoding,
                key_format=key_format,
                passphrase=passphrase
            )

            passphrase_bytes = None if passphrase is None \
                else passphrase.encode('utf-8', errors='ignore')

            self.assertTrue(private_key is not None)

            self.assertEqual(private_key.key_name, 'Test')
            self.assertEqual(private_key.encryption_schema, schema)
            self.assertEqual(private_key.key_size, key_size)
            self.assertEqual(private_key.elliptic_curve, curve_name)
            self.assertEqual(private_key.encoding, key_encoding)
            self.assertEqual(private_key.format, key_format)
            self.assertEqual(private_key.passphrase, passphrase)

            loaded_primitive_key_bytes_1 = \
                private_key.to_primitive_private_key_bytes(
                    decrypt_password=passphrase_bytes,
                    encrypt_password=None
                )

            loaded_primitive_key_bytes_2 = \
                private_key.to_primitive_private_key_bytes(
                    decrypt_password=passphrase_bytes,
                    encrypt_password=None
                )

            self.assertEqual(
                loaded_primitive_key_bytes_1,
                loaded_primitive_key_bytes_2
            )

    @classmethod
    def is_valid_init_combination(
            cls,
            combination: Tuple[
                EncryptionSchema,
                Optional[str],
                Optional[str],
                str,
                str,
                Optional[str]
            ]
    ) -> bool:
        (
            schema,
            key_size,
            curve,
            key_format,
            key_encoding,
            passphrase
        ) = combination

        if schema == EncryptionSchema.RSA and curve is not None:
            return False

        if schema == EncryptionSchema.DSA and curve is not None:
            return False

        if schema == EncryptionSchema.EC and key_size is not None:
            return False

        if schema == EncryptionSchema.DSA \
                and key_size == PrivateKeySize.BIT_4096:
            return False

        if key_size is None and curve is None:
            return False

        # The Cryptography package doesn't support load from a key encoded
        # with OpenSSH format.
        if key_encoding == Encoding.OPEN_SSH:
            return False

        if key_encoding == Encoding.DER \
                and key_format != PrivateFormat.PKCS8 \
                and passphrase is not None:
            return False

        return True
