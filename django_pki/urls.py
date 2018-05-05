from django.contrib import admin
from django.urls import path


from .views import Index

app_name = "pki"

urlpatterns = [
    path('', Index.as_view(), name='index'),

    path('cert/', Index.as_view(), name='certs'),
    path('private-key/', Index.as_view(), name='private-keys'),
    path('csr/', Index.as_view(), name='csrs'),
    path('crl/', Index.as_view(), name='crls'),

    path('private-key/add', Index.as_view(), name='private_key_add'),
    path('private-key/<id:pk>', Index.as_view(), name='private_key_update'),
    path('private-key/<id:pk>/delete', Index.as_view(), name='private_key_delete'),

    path('csr/add', Index.as_view(), name='csr_add'),
    path('csr/<id:pk>', Index.as_view(), name='csr_update'),
    path('csr/<id:pk>/delete', Index.as_view(), name='csr_delete'),

    path('cert/add', Index.as_view(), name='cert_add'),
    path('cert/<id:pk>', Index.as_view(), name='cert_update'),
    path('cert/<id:pk>/revoke', Index.as_view(), name='cert_revoke'),
    path('cert/<id:pk>/delete', Index.as_view(), name='cert_delete'),
    path('cert/crl', Index.as_view(), name='cert_crl_index'),
    path('cert/<id:pk>/crl', Index.as_view(), name='cert_crl_update'),
    path('cert/<id:pk>/ocsp', Index.as_view(), name='cert_ocsp_update'),

    path('crl/add', Index.as_view(), name='crl_add'),
    path('crl/<id:pk>', Index.as_view(), name='crl_update'),
    path('crl/<id:pk>/delete', Index.as_view(), name='crl_delete'),
]
