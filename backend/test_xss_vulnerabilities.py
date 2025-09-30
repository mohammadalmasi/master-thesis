
# ============================================================================
# XSS VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_xss_high_1():
    """F-string with HTML and user input"""
    user_name = request.args.get("name")
    return f"<h1>Welcome {user_name}!</h1>"

def vulnerable_xss_high_2():
    """Direct innerHTML manipulation"""
    content = request.form.get("content")
    script = f"document.getElementById('content').innerHTML = '{content}'"

def vulnerable_xss_high_3():
    """eval() with user input"""
    user_code = request.args.get("code")
    result = eval("calculate_" + user_code)

# ============================================================================
# XSS VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_xss_medium_1():
    """Using |safe filter (potential XSS if not validated)"""
    user_html = "{{ user_content|safe }}"

def vulnerable_xss_medium_2():
    """Markup() usage"""
    from markupsafe import Markup
    user_input = request.args.get("input")
    safe_html = Markup(user_input)

def vulnerable_xss_medium_3():
    """URL parameter usage"""
    search_term = URLSearchParams(window.location.search)

def vulnerable_xss_medium_4():
    """jQuery .append() with HTML"""
    data = request.form.get("data")
    script = "$('#result').append('<div>' + data + '</div>')"

# ============================================================================
# XSS VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_xss_low_1():
    """Simple string concatenation"""
    greeting = user_name + " welcome"

def vulnerable_xss_low_2():
    """Template string building"""
    message_template = "Hello " + username
