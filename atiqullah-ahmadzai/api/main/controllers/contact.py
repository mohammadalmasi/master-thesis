"""
Contact
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

def contact(request):
  
    data = [
        {
            "name": "Talaya Farasat",
            "university": "University of Passau",
            "country": "Germany",
            "email": "tf@sec.uni-passau.de"
        },
        {
            "name": "Aleena Elsa George",
            "university": "University of Passau",
            "country": "Germany",
            "email": "aeg@sec.uni-passau.de"
        },
        {
            "name": "Sayed Alisina Qaderi",
            "university": "University of Passau",
            "country": "Germany",
            "email": "qaderi01@ads.uni-passau.de"
        },
        {
            "name": "Atiqullah Ahmadzai",
            "university": "University of Passau",
            "country": "Germany",
            "email": "ahmadz01@ads.uni-passau.de"
        },
        {
            "name": "Dusan Dordevic",
            "university": "University of Passau",
            "country": "Germany",
            "email": "dordev01@ads.uni-passau.de"
        },
        {
            "name": "Joachim Posegga",
            "university": "University of Passau",
            "country": "Germany",
            "email": "jp@sec.uni-passau.de"
        }
    ]
    context = {
            'title': os.getenv('SITE_TITLE')+" - Contact",
            'data':data

        }
    return render(request, 'contact.html', context)