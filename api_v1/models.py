from django.contrib.auth.models import User
from django.db import models
import uuid

# Create your models here.


class Owner(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    enabled = models.BooleanField(default=True)

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    updated = models.DateTimeField(auto_now=True, auto_now_add=False)
    created = models.DateTimeField(auto_now=False, auto_now_add=True)

    def __str__(self):
        return self.user.username


class SysUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    owner = models.ForeignKey(Owner, on_delete=models.CASCADE)

    enabled = models.BooleanField(default=True)
    last_seen = models.DateTimeField(auto_now=True)
    extra_info = models.TextField(blank=True, null=True)

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    updated = models.DateTimeField(auto_now=True, auto_now_add=False)
    created = models.DateTimeField(auto_now=False, auto_now_add=True)

    def __str__(self):
        return self.user.username


class Service(models.Model):
    owner = models.ForeignKey(Owner, on_delete=models.CASCADE)

    name = models.CharField(max_length=30)
    url = models.URLField()
    enabled = models.BooleanField(default=True)
    last_seen = models.DateTimeField(auto_now=True)
    ssl_properties = models.TextField()

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    updated = models.DateTimeField(auto_now=True, auto_now_add=False)
    created = models.DateTimeField(auto_now=False, auto_now_add=True)

    def __str__(self):
        return self.name
