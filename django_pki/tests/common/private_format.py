from django.test import TestCase

from ...common import PrivateFormat


class PrivateFormatTest(TestCase):
    def test_get_available_private_formats_returns_a_list_of_private_format_elements(
            self):
        private_formats = PrivateFormat.get_available_private_formats()

        self.assertTrue(isinstance(private_formats, list))

        for each in private_formats:
            self.assertTrue(isinstance(each, PrivateFormat))

    def test_each_available_private_format_has_a_corresponding_serialization_object(self):
        private_format = PrivateFormat.get_available_private_formats()
        for each in private_format:
            try:
                each.get_serialization_object()
            except ValueError:
                self.fail(
                    'Private format %s does not have a corresponding \
serialization object.'
                )
            finally:
                pass
