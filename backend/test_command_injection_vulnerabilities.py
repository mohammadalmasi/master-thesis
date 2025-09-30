# ============================================================================
# COMMAND INJECTION VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_command_1():
    """Direct os.system with user input"""
    user_input = request.form.get('filename')
    os.system("ls -la " + user_input)  # Command injection vulnerability

def vulnerable_command_2():
    """subprocess.call with shell=True"""
    filename = request.args.get('file')
    subprocess.call("cat " + filename, shell=True)  # Command injection vulnerability

def vulnerable_command_3():
    """os.popen with concatenated input"""
    directory = request.form.get('dir')
    result = os.popen("ls " + directory).read()  # Command injection vulnerability
    return result

def vulnerable_command_4():
    """eval with user input"""
    code = request.form.get('code')
    eval("print('" + code + "')")  # Code injection vulnerability

def vulnerable_command_5():
    """exec with user input"""
    command = request.form.get('cmd')
    exec("os.system('" + command + "')")  # Code injection vulnerability

def vulnerable_command_6():
    """subprocess.run with shell=True"""
    user_cmd = request.form.get('command')
    subprocess.run(user_cmd, shell=True)  # Command injection vulnerability

def vulnerable_command_7():
    """subprocess.Popen with shell=True"""
    cmd = request.form.get('cmd')
    subprocess.Popen(cmd, shell=True)  # Command injection vulnerability

def vulnerable_command_8():
    """Dynamic import with user input"""
    module_name = request.form.get('module')
    __import__(module_name)  # Code injection vulnerability

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_command_9():
    """os.remove with user input"""
    filepath = request.form.get('file')
    os.remove("/tmp/" + filepath)  # Path traversal vulnerability

def vulnerable_command_10():
    """Template injection"""
    from string import Template
    template_str = request.form.get('template')
    template = Template("Hello $name")
    result = template.substitute(name=template_str)  # Template injection vulnerability

# ============================================================================
# COMMAND INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_command_low_1():
    """Basic string concatenation with user input"""
    user_input = request.form.get('input')
    message = "Command: " + user_input  # Low severity - just string concatenation

def vulnerable_command_low_2():
    """Simple variable assignment with user input"""
    filename = request.args.get('file')
    command = "ls " + filename  # Low severity - command construction without execution

def vulnerable_command_low_3():
    """Path construction with user input"""
    user_path = request.form.get('path')
    full_path = "/home/user/" + user_path  # Low severity - path construction

def vulnerable_command_low_4():
    """Environment variable with user input"""
    env_var = request.args.get('env')
    os.environ['CUSTOM_VAR'] = env_var  # Low severity - environment variable setting

def vulnerable_command_low_5():
    """Configuration with user input"""
    config_value = request.form.get('config')
    config = {"setting": config_value}  # Low severity - configuration setting

# ============================================================================
# COMMAND INJECTION SAFE FUNCTIONS
# ============================================================================

def safe_command_1():
    """Safe subprocess usage"""
    filename = request.form.get('file')
    # Input validation
    if not filename or '..' in filename or '/' in filename:
        return "Invalid filename"
    
    # Safe subprocess usage
    subprocess.run(['ls', '-la', filename], shell=False)

def safe_command_2():
    """Safe os.path operations"""
    import os.path
    directory = request.form.get('dir')
    # Input validation
    if not directory or '..' in directory:
        return "Invalid directory"
    
    # Safe path operations
    safe_path = os.path.join('/safe/base/path', directory)
    if os.path.exists(safe_path):
        return "Directory exists"
