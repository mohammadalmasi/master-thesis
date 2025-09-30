"""
Dashboard
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
from django.contrib.auth.models import User
from django.contrib import messages
from .decorators import block_user
from main.helpers.functions import *

#load login view
@block_user()
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def home(request):
    users = User.objects.exclude(username="admin")
    context = {
        'title': os.getenv('SITE_TITLE')+" - Users",
        'users': users,
    }
    return render(request, 'users.html', context)

#update profile
@login_required
def update_profile(request):
    
    password = request.POST['old_password']
    user     = authenticate(request, username=request.user.username, password=password)
    if(user):
        messages.success(request, 'Success! profile updated.')
        user = User.objects.get(username=request.user.username)
        user.set_password(request.POST['password'])
        user.save()
    else:
        messages.error(request, 'Failed! old password is incorrect.')


    context = {
        'title': os.getenv('SITE_TITLE')+" - Users",
    }

    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)

#register user
@block_user()
@login_required
def register_user(request):
    
    password = request.POST['password']
    confirm  = request.POST['confirm_password']
    username = request.POST['username']
    email    = request.POST['email']
    
    if User.objects.filter(username=username):
        messages.error(request, 'Error! username already exist.')
    else:
        user = User.objects.create(username=username)
        user.set_password(password)
        user.email = email
        user.save()

        messages.success(request, 'Success! user registered.')


    context = {
        'title': os.getenv('SITE_TITLE')+" - Users",
    }

    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)

#delete user
@block_user()
@login_required
def delete_user(request,id):
    
    user  = User.objects.get(id=id)
    user.delete()

    messages.success(request, 'Success! user deleted.')
    context = {
        'title': os.getenv('SITE_TITLE')+" - Users",
    }

    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)


#update profile
@block_user()
@login_required
def update_user(request):
    
    id       = request.POST['user_id']
    username = request.POST['username']
    email    = request.POST['email']
    password = request.POST['password']

    print(password)
    
    user = User.objects.get(id=id)
    if(user):
        user.username = username
        user.email = email
        user.set_password(password)
        user.save()
        
        messages.success(request, 'Success! user updated.')
    else:
        messages.error(request, 'Failed! something went wrong.')


    context = {
        'title': os.getenv('SITE_TITLE')+" - Users",
    }

    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)