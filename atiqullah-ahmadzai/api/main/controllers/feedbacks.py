"""
Feedbacks
"""

from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response
from django.contrib.sites.shortcuts import get_current_site
from urllib.parse import urlsplit, parse_qs
from werkzeug.datastructures import MultiDict
from django.shortcuts import redirect
from django.shortcuts import render
import os
from django.contrib.auth.decorators import login_required
from main.models.feedback import Feedback
from django.contrib import messages
from .decorators import block_user
from main.helpers.functions import *


#load login view
@block_user()
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def home(request):
    feedbacks = Feedback.objects.all()
    context = {
        'title': os.getenv('SITE_TITLE')+" - Feedbacks",
        'feedbacks':feedbacks
    }
    return render(request, 'feedbacks.html', context)

#save feedback
@login_required
def save_feedback(request):
    
    subject    = request.POST['subject']
    body       = request.POST['body']
    

    feedback = Feedback.objects.create()
    feedback.subject = subject
    feedback.body    = body
    feedback.user_id = request.user.id
    feedback.save()
    messages.success(request, 'Success! feedback saved.')


    context = {
        'title': os.getenv('SITE_TITLE')+" - Users",
    }

    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)