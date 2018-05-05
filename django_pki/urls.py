from django.contrib import admin
from django.urls import path


from .views import Index

app_name = "pki"

urlpatterns = [
    path('', Index.as_view(), name='index'),
]