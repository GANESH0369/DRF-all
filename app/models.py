from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    username=models.CharField(default=None, max_length=50)
    password=models.CharField(default=None, max_length=180)
    # mobile = models.CharField(default=None, max_length=15, blank=True, null=True)
    