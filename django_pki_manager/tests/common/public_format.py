from django.test import TestCase

from ...common import PublicFormat


class PublicFormatTest(TestCase):
    def test_get_available_encodings_returns_a_list_of_public_format_elements(
            self):
        public_formats = PublicFormat.get_available_public_formats()

        self.assertTrue(isinstance(public_formats, list))

        for each in public_formats:
            self.assertTrue(isinstance(each, PublicFormat))

    def test_each_available_public_format_has_a_corresponding_serialization_object(self):
        public_format = PublicFormat.get_available_public_formats()
        for each in public_format:
            try:
                each.get_serialization_object()
            except ValueError:
                self.fail(
                    'Encoding %s does not have a corresponding serialization \
object.'
                )
            finally:
                pass
