from django.db import models
from django.contrib.auth.models import User

class Feedback(models.Model):
    id              = models.BigAutoField(primary_key=True)
    user            = models.ForeignKey(User, on_delete=models.CASCADE)
    subject         = models.TextField()
    body            = models.TextField()
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)