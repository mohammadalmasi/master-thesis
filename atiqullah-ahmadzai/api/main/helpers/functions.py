from django.conf import settings 
from django.db import connection
import math
import re
from urllib.parse import urlparse, urlunparse, parse_qs
from django.urls import reverse
import os
import requests
from main.models.project import Project
from datetime import datetime
from django.contrib.auth.models import Group


#GIT Pull
import shutil
import git
import environ

def init_error_codes():
    rsp = {}
    rsp['200']     = "Operation Successful"
    rsp['400']     = "Invalid input data"
    rsp['401']     = "Incorrect username or password"
    rsp['403']     = "Invalid API key"
    rsp['403_2']   = "Your input contains words that may cause to hurt someone, please try with safer words"
    rsp['500']     = "Your request can not be completed at this moment, please try again"
    return rsp

def get_env(value):
    env = environ.Env()
    environ.Env.read_env()
    return env(value)

def parse_response(data={},msg="Operation failed",status=False):
    return {"status_code":status, "message":msg, "data":data}

def append_query_param(url, param_name, param_value):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    query_params[param_name] = [param_value]
    updated_query = '&'.join([f"{k}={v[0]}" for k, v in query_params.items()])
    updated_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        updated_query,
        parsed_url.fragment
    ))

    return updated_url

def get_prev_url(request):
    url = request.META.get('HTTP_REFERER')
    if url:
        return url
    else:
        return reverse('home')
    


def pretty_print_docs(docs):
    print(f"\n{'-' * 100}\n".join([f"Document {i+1}:\n\n" + d.page_content for i, d in enumerate(docs)]))

def pull_project_repo(id):
    project  = Project.objects.get(id=id)
    project_path     = os.path.join(settings.MEDIA_ROOT, project.uid)
    repo_path        = os.path.join(settings.MEDIA_ROOT, "repo"+"/"+project.uid)

    if not os.path.exists(repo_path):
        os.makedirs(repo_path)

    repo = git.Repo.clone_from(project.repo_url, repo_path)
    
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
                source_file = os.path.join(root, file)
                destination_file = os.path.join(project_path, file)
                shutil.copy2(source_file, destination_file)
    
    shutil.rmtree(repo_path)
    return True


def get_files(project):
    path    = "uploads/"+project.uid
    files   = []
    if not os.path.exists(path):
            os.makedirs(path)
    file_names = os.listdir(path)
    for file_name in file_names:
        if file_name != "chroma_db":
            file_path = os.path.join(path, file_name)

            size = round((os.path.getsize(file_path))/1024,2)
            modification_time = os.path.getmtime(file_path)
            modification_date = datetime.fromtimestamp(modification_time).strftime('%Y-%m-%d')

            if ".py" in file_name:
                files.append({'name':file_name,'date':modification_date,'size':size})
    return files


def is_admin(user):
    return user.groups.filter(name='admin').exists()