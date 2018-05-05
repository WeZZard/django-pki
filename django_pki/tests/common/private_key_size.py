from django.test import TestCase

from ...common import PrivateKeySize


class PrivateKeySizeTest(TestCase):
    def test_get_available_private_key_sizes_returns_a_list_of_private_key_size_elements(
            self):
        private_key_sizes = PrivateKeySize.get_available_private_key_sizes()

        self.assertTrue(isinstance(private_key_sizes, list))

        for each in private_key_sizes:
            self.assertTrue(isinstance(each, PrivateKeySize))

    def test_each_available_private_key_size_has_a_corresponding_int_value(self):
        private_key_size = PrivateKeySize.get_available_private_key_sizes()
        for each in private_key_size:
            try:
                each.to_int()
            except ValueError:
                self.fail(
                    'Private key size %s does not have a corresponding \
serialization object.'
                )
            finally:
                pass
