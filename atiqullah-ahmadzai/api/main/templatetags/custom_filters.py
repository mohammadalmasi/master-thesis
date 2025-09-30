from django import template
import re
from django.contrib.auth.models import Group

register = template.Library()

@register.filter(name='extract_file_name')
def extract_file_name(value):
    pattern = r'#File Name:\s*([^ \n]+)'
    match = re.search(pattern, value)

    if match:
        return match.group(1)
    else:
        return "No file name found."
    
@register.filter(name='is_user_admin')
def is_user_admin(user):
    return user.groups.filter(name="admin").exists()