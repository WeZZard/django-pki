from django.test import TestCase

from ...common import Encoding


class EncodingTest(TestCase):
    def test_get_available_encodings_returns_a_list_of_encoding_elements(self):
        encodings = Encoding.get_available_encodings()

        self.assertTrue(isinstance(encodings, list))

        for each in encodings:
            self.assertTrue(isinstance(each, Encoding))

    def test_each_available_encoding_has_a_corresponding_serialization_object(self):
        encodings = Encoding.get_available_encodings()
        for each in encodings:
            try:
                each.get_serialization_object()
            except ValueError:
                self.fail(
                    'Encoding %s does not have a corresponding serialization \
object.'
                )
            finally:
                pass
