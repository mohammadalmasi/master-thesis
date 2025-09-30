"""main URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

#custom controllers
from .controllers import auth
from .controllers import dashboard
from .controllers import users
from .controllers import feedbacks
from .controllers import response
from .controllers import project
from .controllers import contact

urlpatterns = [
    path('admin/', admin.site.urls),

    #load login page
    path('login', auth.login_page, name="login"),
    path('check_login', auth.check_login, name='check_login'),
    
    path('register', auth.register_page, name="register"),
    path('register_new_user', auth.register_new_user, name='register_new_user'),
    path('logout', auth.user_logout, name='logout'),

    #dashboard URLs
    path('', dashboard.home, name="home"),
    path('users', users.home, name="users"),

    #projects
    path('projects', project.home, name="projects"),
    path('project/add', project.save_project, name="save_project"),
    path('project/files/<int:id>', project.project_files, name="project_files"),
    path('project/file/delete/<int:id>/<str:name>', project.delete_file, name="delete_file"),
    path('project/delete/<int:id>', project.delete_project, name="delete_project"),
    path('project/<int:id>/file/upload', project.upload_file, name="upload_file"),
    path('project/ask/<int:id>', project.ask_ai, name="ask_ai"),
    path('project/stream_gpt/<int:id>', project.stream_gpt, name="stream_gpt"),
    path('project/vector/reload/<int:id>', project.convert_to_vector, name="convert_to_vector"),
    path('project/repo/pull/<int:id>', project.pull_repo, name="pull_repo"),
    path('project/downnload_result/<int:id>/<str:file>/<str:mode>', project.download_file, name="download_result"),
    path('project/download_report/<int:id>', project.download_report, name="download_report"),



    #users
    path('profile/update', users.update_profile, name="update_profile"),
    path('user/register', users.register_user, name="register_user"),
    path('user/delete/<int:id>', users.delete_user, name="delete_user"),
    path('user/update', users.update_user, name="update_user"),

    #feedbacks
    path('feedbacks', feedbacks.home, name="feedbacks"),
    path('feedback/add', feedbacks.save_feedback, name="save_feedback"),

    #responses
    path('responses', response.home, name="responses"),
    path('response/<int:id>', response.single_response, name="single_response"),

    path('contact', contact.contact, name="contact"),


]
