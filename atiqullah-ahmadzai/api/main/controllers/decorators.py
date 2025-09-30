# decorators.py
from django.http import HttpResponseForbidden
from django.contrib import messages
from django.shortcuts import redirect
from main.helpers.functions import *

def block_user():
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            # Check if the user is the one you want to block
            if not is_admin(request.user):
                messages.error(request, 'Forbidden! you are not authorized to access this URL.')
                return redirect('home')
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator