from django.db.models import Model
from django.db.models.fields import CharField
from django.db.models import ForeignKey
from django.db.models import SET_NULL

from enumfields import EnumField

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .private_key import PrivateKey

from ..common import HashAlgorithm


class Csr(Model):
    subject_name: CharField = CharField()

    private_key: ForeignKey = ForeignKey(
        to=PrivateKey,
        on_delete=SET_NULL,
        related_name='csrs'
    )

    extensions: str

    hash_algorithm: EnumField = EnumField(
        HashAlgorithm
    )

    pass
