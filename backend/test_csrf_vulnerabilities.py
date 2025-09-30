#!/usr/bin/env python3
"""
Test file for CSRF vulnerabilities (all severities)
This file contains intentional security vulnerabilities for testing purposes.
DO NOT use this code in production!
"""



# ============================================================================
# CSRF VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_csrf_high_1():
    """Flask route with POST method without CSRF protection"""
    from flask import Flask, request, render_template
    
    app = Flask(__name__)
    
    @app.route('/submit', methods=['POST'])
    def submit_form():
        data = request.form.get('data')
        # Process form data without CSRF protection
        return render_template('result.html', data=data)

def vulnerable_csrf_high_2():
    """Django view with CSRF exemption and POST handling"""
    from django.views.decorators.csrf import csrf_exempt
    from django.http import HttpResponse
    
    @csrf_exempt
    def process_form(request):
        if request.method == 'POST':
            data = request.POST.get('data')
            # Process form data without CSRF protection
            return HttpResponse("Data processed")

def vulnerable_csrf_high_3():
    """Direct form processing without CSRF validation"""
    from flask import request
    
    if request.method == 'POST':
        form_data = request.form
        # Process form data directly without CSRF validation
        username = form_data.get('username')
        password = form_data.get('password')

def vulnerable_csrf_high_4():
    """HTML form with POST method missing CSRF token"""
    html_form = """
    <form method="post" action="/submit">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Submit">
    </form>
    """
    return html_form

def vulnerable_csrf_high_5():
    """AJAX POST request without CSRF headers"""
    ajax_code = """
    $.ajax({
        url: '/api/submit',
        method: 'POST',
        data: {username: 'test', password: 'test'},
        success: function(response) {
            console.log('Success');
        }
    });
    """
    return ajax_code

def vulnerable_csrf_high_6():
    """Fetch API POST request without CSRF headers"""
    fetch_code = """
    fetch('/api/submit', {
        method: 'POST',
        body: JSON.stringify({username: 'test', password: 'test'}),
        headers: {
            'Content-Type': 'application/json'
        }
    });
    """
    return fetch_code

# ============================================================================
# CSRF VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_csrf_medium_1():
    """Form using GET method for state-changing operations"""
    html_form = """
    <form method="get" action="/delete">
        <input type="hidden" name="id" value="123">
        <input type="submit" value="Delete">
    </form>
    """
    return html_form

def vulnerable_csrf_medium_2():
    """Cookie set without SameSite attribute"""
    from flask import make_response
    
    response = make_response("Cookie set")
    response.set_cookie('session_id', 'abc123')
    return response

def vulnerable_csrf_medium_3():
    """Cookie set without Secure flag"""
    from flask import make_response
    
    response = make_response("Cookie set")
    response.set_cookie('session_id', 'abc123', httponly=True)
    return response

def vulnerable_csrf_medium_4():
    """Form without proper input validation"""
    html_form = """
    <form method="post" action="/submit">
        <input type="text" name="data">
        <input type="submit" value="Submit">
    </form>
    """
    return html_form

# ============================================================================
# CSRF VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_csrf_low_1():
    """Form without explicit method attribute"""
    html_form = """
    <form action="/submit">
        <input type="text" name="data">
        <input type="submit" value="Submit">
    </form>
    """
    return html_form

def vulnerable_csrf_low_2():
    """Form without explicit action attribute"""
    html_form = """
    <form method="post">
        <input type="text" name="data">
        <input type="submit" value="Submit">
    </form>
    """
    return html_form

def vulnerable_csrf_low_3():
    """Text input without CSRF protection context"""
    html_input = """
    <input type="text" name="username" placeholder="Enter username">
    """
    return html_input

# ============================================================================
# CSRF SAFE FUNCTIONS
# ============================================================================

def safe_csrf_1():
    """Flask route with CSRF protection"""
    from flask import Flask, request, render_template
    from flask_wtf.csrf import CSRFProtect
    
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your-secret-key'
    csrf = CSRFProtect(app)
    
    @app.route('/submit', methods=['POST'])
    def submit_form():
        data = request.form.get('data')
        # Form is protected by CSRF token
        return render_template('result.html', data=data)

def safe_csrf_2():
    """Django view with CSRF protection"""
    from django.shortcuts import render
    from django.views.decorators.csrf import ensure_csrf_cookie
    
    @ensure_csrf_cookie
    def process_form(request):
        if request.method == 'POST':
            data = request.POST.get('data')
            # Form is protected by Django's CSRF middleware
            return render(request, 'result.html', {'data': data})

def safe_csrf_3():
    """HTML form with CSRF token"""
    html_form = """
    <form method="post" action="/submit">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" value="Submit">
    </form>
    """
    return html_form

def safe_csrf_4():
    """AJAX request with CSRF headers"""
    ajax_code = """
    $.ajax({
        url: '/api/submit',
        method: 'POST',
        data: {username: 'test', password: 'test'},
        headers: {
            'X-CSRF-Token': $('meta[name="csrf-token"]').attr('content')
        },
        success: function(response) {
            console.log('Success');
        }
    });
    """
    return ajax_code

def safe_csrf_5():
    """Cookie with proper security attributes"""
    from flask import make_response
    
    response = make_response("Cookie set")
    response.set_cookie(
        'session_id', 
        'abc123', 
        httponly=True, 
        secure=True, 
        samesite='Strict'
    )
    return response 