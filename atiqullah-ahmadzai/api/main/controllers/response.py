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
from django.contrib.sites.shortcuts import get_current_site
from urllib.parse import urlsplit, parse_qs
from werkzeug.datastructures import MultiDict
from django.shortcuts import redirect
from django.shortcuts import render
import os
from django.contrib.auth.decorators import login_required
from main.models.response import Response
from main.models.log import Log
from django.contrib import messages
from .decorators import block_user
from main.helpers.functions import *
from rest_framework.response import Response as DResponse
import re
from django.http import JsonResponse, HttpResponseBadRequest


#load login view
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def home(request):
    if is_admin(request.user):
        responses = Response.objects.order_by("-id").all()
    else:
        responses = Response.objects.filter(user_id=request.user.id).order_by("-id")
        
    
    context = {
        'title': os.getenv('SITE_TITLE')+" - Feedbacks",
        'responses':responses
    }
    return render(request, 'responses.html', context)

@csrf_exempt
@login_required
def single_response(request,id):
    response = Response.objects.filter(id=id).values()[0]
    return JsonResponse(response)
