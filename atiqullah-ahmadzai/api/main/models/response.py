from django.db import models
from django.contrib.auth.models import User
from main.models.project import Project

def default_json():
    return {}

class Response(models.Model):

    id              = models.BigAutoField(primary_key=True)
    user            = models.ForeignKey(User, on_delete=models.CASCADE)
    request         = models.JSONField(default=default_json)
    response        = models.TextField()
    r_type          = models.CharField(max_length=100,default="")
    model           = models.CharField(max_length=100,default="")
    mode            = models.CharField(max_length=100,default="")
    tokens          = models.IntegerField(default=0)
    project         = models.ForeignKey(Project, on_delete=models.CASCADE)
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)