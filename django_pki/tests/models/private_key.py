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
        passphrases = [None, b'password']
        available_private_key_sizes: List[Optional[PrivateKeySize]] = \
            PrivateKeySize.get_available_private_key_sizes()
        available_private_key_sizes.append(None)
        available_elliptic_curves: List[Optional[EllipticCurve]] = \
            EllipticCurve.get_available_elliptic_curves()
        available_elliptic_curves.append(None)

        combinations = list(product(
            EncryptionSchema.get_available_encryption_schemas(),
            available_private_key_sizes,
            available_elliptic_curves,
            PrivateFormat.get_available_private_formats(),
            Encoding.get_available_encodings(),
            passphrases,
        ))

        for each_combination in filter(
                type(self).is_valid_init_combination,
                combinations
        ):
            (
                schema,
                size,
                ec,
                fmt,
                enc,
                passphrase
            ) = each_combination

            print(each_combination)

            private_key: Optional[PrivateKey] = None

            try:
                private_key = PrivateKey.make(
                    name='Test',
                    encryption_schema=schema,
                    key_size=size,
                    elliptic_curve=ec,
                    encoding=enc,
                    private_format=fmt,
                    passphrase=passphrase
                )
            except ValueError:
                self.fail('Fuck')
            finally:
                self.assertTrue(private_key is not None)
                self.assertEqual(private_key.name, 'Test')
                self.assertEqual(private_key.encryption_schema, schema)
                self.assertEqual(private_key.key_size, size)
                self.assertEqual(private_key.elliptic_curve, ec)
                self.assertEqual(private_key.encoding, enc)
                self.assertEqual(private_key.private_format, fmt)
                self.assertEqual(private_key.passphrase, passphrase)

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
        (schema, pk_size, ec, ft, encoding, passphrase) = combination
        if encoding == Encoding.OpenSSH:
            return False
        if encoding == Encoding.DER and ft == PrivateFormat.TraditionalOpenSSL:
            return False
        if schema == EncryptionSchema.RSA:
            return pk_size is not None and ec is None and pk_size != PrivateKeySize.BIT_3072
        if schema == EncryptionSchema.DSA:
            return pk_size is not None and ec is None and pk_size != PrivateKeySize.BIT_4096
        if schema == EncryptionSchema.EC:
            return pk_size is None and ec is not None
        raise ValueError('Invalid encryption schema: {s}.'.format(s=schema))
