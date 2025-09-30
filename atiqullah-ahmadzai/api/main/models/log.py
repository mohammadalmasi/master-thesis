from django.db import models
from django.contrib.auth.models import User


class Log(models.Model):

    id              = models.BigAutoField(primary_key=True)
    user            = models.CharField(max_length=100,default="")
    url             = models.CharField(max_length=100,default="")
    agent           = models.CharField(max_length=255,default="")
    ip              = models.CharField(max_length=100,default="")
    method          = models.CharField(max_length=100,default="")
    status_code     = models.CharField(max_length=100,default="")
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)