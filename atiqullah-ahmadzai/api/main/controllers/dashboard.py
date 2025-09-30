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

from main.models.feedback import Feedback
from main.models.response import Response
from django.contrib.auth.models import User
from main.models.price import Price

from django.db.models import Count
from django.db.models import Sum
from django.db.models.functions import ExtractMonth, ExtractYear
from django.utils import timezone
from main.helpers.functions import *
from main.helpers.poe import *

#load dashboard view
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def home(request):
    
    #ask_poe("test")
    #diagram chart data 12 months
    current_year = timezone.now().year
    current_month = timezone.now().month
    data = [0] * 12

    monthly_counts = Response.objects.filter(
        created_at__year=current_year
    )
    
    if is_admin(request.user):
        monthly_counts = monthly_counts.filter(user_id=request.user.id)

    monthly_counts = monthly_counts.annotate(
        month=ExtractMonth('created_at')
    ).values(
        'month'
    ).annotate(
        count=Count('id')
    ).order_by(
        'month'
    )

    for entry in monthly_counts:
        month = entry['month']
        count = entry['count']
        data[month - 1] = count

    if current_month < 12:
        data[current_month:] = [0] * (12 - current_month)


    if is_admin(request.user):
        context = {
            'title': os.getenv('SITE_TITLE')+" - Dashboard",
            'responses':Response.objects.count(),
            'lstm':Response.objects.filter(model="LSTM").count(),
            'feedbacks':Feedback.objects.count(),
            'gpt': Response.objects.filter(model="GPT").count() ,
            'history_data' : ', '.join(map(str, data))
        }
    else:

        context = {
            'title': os.getenv('SITE_TITLE')+" - Dashboard",
            'responses':Response.objects.filter(user_id=request.user.id).count(),
            'lstm':Response.objects.filter(model="LSTM",user_id=request.user.id).count(),
            'feedbacks':Feedback.objects.filter(user_id=request.user.id).count(),
            'gpt': Response.objects.filter(model="GPT",user_id=request.user.id).count(),
            'history_data' : ', '.join(map(str, data))
        }
    print(context)
    return render(request, 'dashboard.html', context)


#load login view
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def docs(request):
    
    return render(request, 'docs.html')