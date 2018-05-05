from django.test import TestCase

from ...common import EncryptionSchema


class EncryptionSchemaTest(TestCase):
    def test_get_available_encryption_schemas_returns_a_list_of_encryption_schema_elements(self):
        schemas = EncryptionSchema.get_available_encryption_schemas()

        self.assertTrue(isinstance(schemas, list))

        for each in schemas:
            self.assertTrue(isinstance(each, EncryptionSchema))
