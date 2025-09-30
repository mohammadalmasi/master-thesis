"""
Login and redirect to dashboard
"""

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
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
from django.http import HttpResponse
from django.shortcuts import redirect
from django.contrib import messages
from main.helpers.functions import *
from django.contrib.auth.models import User


#load login view
@csrf_exempt
@permission_classes((AllowAny,))
def login_page(request):
    success = request.GET.get('success')
    context = {
        'title': os.getenv('SITE_TITLE'),
        'success':success
    }
    return render(request, 'login.html', context)
# Load register page
@csrf_exempt
@permission_classes((AllowAny,))
def register_page(request):
    success = request.GET.get('success')
    context = {
        'title': os.getenv('SITE_TITLE'),
        'success':success
    }
    return render(request, 'register.html', context)

@api_view(["POST"])
@permission_classes((AllowAny,))
def register_new_user(request):
    email    = request.POST['email']
    password = request.POST['password']

    confirm_password = request.POST['confirm-password']
    if(password != confirm_password):
        messages.error(request, "Passwords do not match")
        return redirect('register')
    
    if User.objects.filter(email=email).exists():
        messages.error(request, "User already exists")
        return redirect('register')
    
    user = User.objects.create_user(email, email, password)
    user.save()
    messages.success(request, "Account created successfully")
    return redirect('login')


#login with username and password
@api_view(["POST"])
@permission_classes((AllowAny,))
def check_login(request):
    email    = request.POST['email']
    password = request.POST['password']
    
    user = authenticate(request, username=email, password=password)
  
    if(user):
        messages.success(request, "Welcome back! lets optimize your code.")
        login(request, user)
        return redirect('home')
    else:
        previous_url = request.META.get('HTTP_REFERER')
        update_url = append_query_param(previous_url,"success","false")
        messages.error(request, "Invalid email or password")
        return redirect(update_url)
    

#login with username and password

@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def user_logout(request):
    logout(request)
    return redirect('login')
