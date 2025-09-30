"""
Feedbacks
"""

from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.response import Response as DResponse
from django.contrib.sites.shortcuts import get_current_site
from urllib.parse import urlsplit, parse_qs
from werkzeug.datastructures import MultiDict
from django.shortcuts import redirect
from django.shortcuts import render
import os
from django.contrib.auth.decorators import login_required
from main.models.project import Project
from main.models.response import Response
from django.contrib import messages
from .decorators import block_user
from main.helpers.functions import *
from main.helpers.poe import *
from django.http import HttpResponse
from django.http import JsonResponse, HttpResponseBadRequest
import glob
from datetime import datetime
import threading
import subprocess
import os
import platform
import json
from django.http import StreamingHttpResponse
from poe_api_wrapper import PoeApi
from django.template.loader import get_template
import threading



#load main view
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def home(request):
    if is_admin(request.user):
        projects = Project.objects.order_by("-id").all()
    else:
        projects = Project.objects.filter(user_id=request.user.id).order_by("-id")
        
    context = {
        'title': os.getenv('SITE_TITLE')+" - Projects",
        'projects':projects
    }
    return render(request, 'projects.html', context)

#save project
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def save_project(request):
    name     = request.POST['name']
    desc     = request.POST['description']
    has_repo = request.POST['has_repo']
    repo_url = request.POST['repo_url']

    project = Project.objects.create(user_id=request.user.id)
    project.name        = name
    project.description = desc
    project.has_repo    = has_repo
    project.repo_url    = repo_url
    project.status      = 0

    pr = project.save()

    path    = "uploads/"+project.uid
    if not os.path.exists(path):
        os.makedirs(path)

    messages.success(request, 'Success! project saved, wait a few minutes until all files are processed for AI.')
    if(has_repo == "Yes"):
        th1 = threading.Thread(target=pull_project_repo,args=(project.id,))
        th1.start()
        th1.join()

    context = {
        'title': os.getenv('SITE_TITLE')+" - Projects",
    }

    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)

#load project files
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def project_files(request,id):
    project = Project.objects.get(id=id)
    files   = get_files(project)
    

    context = {
        'title': os.getenv('SITE_TITLE')+" - Files",
        'project':project,
        'files': files
    }
    return render(request, 'files.html', context)

#delete project files
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def delete_file(request,id,name):
    project = Project.objects.get(id=id)
    path    = "uploads/"+project.uid+"/"+name
    if os.path.exists(path):
        os.remove(path)

    messages.success(request, 'Success! file deleted.')
    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)


#delete project
@csrf_exempt
@login_required
def delete_project(request,id):
    
    project  = Project.objects.get(id=id)
    project.delete()
    
    messages.success(request, 'Success! project deleted.')
    previous_url = request.META.get('HTTP_REFERER')
    return redirect(previous_url)

#upload file to project
@csrf_exempt
@login_required
def upload_file(request,id):
    project  = Project.objects.get(id=id)
    if project:
        uploads_folder_path = os.path.join(settings.MEDIA_ROOT, project.uid)
        if not os.path.exists(uploads_folder_path):
            os.makedirs(uploads_folder_path)

        uploaded_file = request.FILES['file']
        destination_path = os.path.join(uploads_folder_path, uploaded_file.name)
        with open(destination_path, 'wb') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        messages.success(request, 'Success! file uploaded.')
        return JsonResponse({'success': True, 'message': 'File uploaded successfully'})
    else:
        return HttpResponseBadRequest()
    
#convert files to vector
@csrf_exempt
@login_required
def convert_to_vector(request,id):
    return HttpResponse(True)

#pull repo
@csrf_exempt
@login_required
def pull_repo(request,id):
    pull_project_repo(id)
    return HttpResponse(1)

#upload file to project
@csrf_exempt
@login_required
def ask_ai(request,id):
    model       = request.POST.get('model', None)
    project = Project.objects.get(id=id)
    file_name = request.POST.get('files[]', None)
    mode      = request.POST.get('mode', None)

    path    = "uploads/"+project.uid
    file_path = os.path.join(path, file_name)
    code    = ""
    
    with open(file_path, 'r') as file:
        
        lines = file.read()
        code = code + "\n #File Name: "+file_name +"\n\n"+lines
        code = code + "\n #End of File Name: "+file_name

    if model == "GPT":
        


        if not os.path.exists(path):
                os.makedirs(path)

        #list files in project directory
   
                
        if  len(code) >= 2000:
            result = "Input code is too lengthy, it should not exceed than 2000 charachters"
        else:
            result = "Request in progress..."#ask_poe(code)
            result = result.rstrip().lstrip().replace("`","")
        #save req and response
        log = Response.objects.create(project=project,model=model,mode=mode,user_id=request.user.id)
        log.request  = code
        log.response = result
        log.user_id  = request.user.id
        log.project_id  = id
        log.save()
    else:

        log = Response.objects.create(project=project,model=model,mode=mode,user_id=request.user.id)
        background_thread = threading.Thread(target=lstm_thread, args=(log,project,mode,file_name, code, request))
        background_thread.start()
        result = "Request in progress..."
        
    rsp = {"result":result,"id":log.id}
    return JsonResponse(rsp)


def lstm_thread(log,project,mode,file_name, code, request):
    if platform.system() == "Windows":
        command = "..\..\env\Scripts\python.exe ..\lib\demonstrate.py "+mode+" "+str(project.uid)+" "+file_name+ " "+str(log.id)
        os.system(command)
    else:
        # Prefer dedicated ML venv if present; fallback to app venv
        ml_python = "../ml310/bin/python"
        app_python = "../env/bin/python"
        python_bin = ml_python if os.path.exists(ml_python) else app_python
        command = python_bin+" ../lib/demonstrate.py "+mode+" "+str(project.uid)+" "+file_name+ " "+str(log.id)
        os.system(command)
        
    result = "<img src='/project/downnload_result/"+str(project.id)+"/"+str(log.id)+"_"+file_name+"/"+mode+"' />"

    
    log.request  = code
    log.response = result
    log.user_id  = request.user.id
    log.project_id  = project.id
    log.save()

def stream_gpt(request,id):
    tokens = {
        'p-b': get_env("POE_PB"),
        'p-lat': get_env("POE_LT")
    }
    client = PoeApi(tokens=tokens)
    log = Response.objects.filter(id=id).first()
    message  = "Please check the below code for issues: "+log.request

    def event_stream():
        for chunk in client.send_message(bot="code-checker-sad", message=message):
            yield f"data: {json.dumps(chunk['text'])}\n\n"
        log.response = chunk["text"]
        log.save()
        yield "data: #END\n\n"
        
    
    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    return response

#load main view
@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def download_file(request,id,file,mode):
    project     = Project.objects.filter(id=id).first()
    path        = "uploads/"+project.uid+"/output/"+file+"_"+mode+".png"
    if os.path.exists(path):
        with open(path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/octet-stream")
            response['Content-Disposition'] = 'inline; filename=' + os.path.basename(path)
            return response
    else:
        return HttpResponse("Image doesnt exist")
    

@csrf_exempt
@login_required
@permission_classes((AllowAny,))
def download_report(request,id):
    project   = Project.objects.filter(id=id).first()
    responses = Response.objects.filter(project=project).values()
    context = {
        'title': os.getenv('SITE_TITLE')+" - Report",
        'project':project,
        'responses':responses,
        'files':get_files(project)
    }


    return render(request, 'report.html', context)