from django.db import models
from django.contrib.auth.models import User
import uuid

def default_json():
    return {}

def generate_uuid():
    return str(uuid.uuid4()).replace('-', '')

class Project(models.Model):
    id              = models.BigAutoField(primary_key=True)
    uid             = models.CharField(max_length=32, default=generate_uuid, editable=False, unique=True)
    name            = models.CharField(max_length=255,default='')
    description     = models.CharField(max_length=255,default='')
    user            = models.ForeignKey(User, on_delete=models.CASCADE, default=None)

    has_repo        = models.CharField(max_length=255,default='')
    repo_url        = models.CharField(max_length=255,default='')

    status          = models.IntegerField(default=0)
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)
