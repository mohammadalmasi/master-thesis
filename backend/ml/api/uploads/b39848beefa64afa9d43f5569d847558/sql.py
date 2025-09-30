
# ============================================================================
# SQL INJECTION VULNERABILITIES (HIGH SEVERITY)
# ============================================================================

def vulnerable_sql_high_1():
    """Direct string concatenation in SELECT"""
    user_id = request.form["user_id"]
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)

def vulnerable_sql_high_2():
    """F-string with SQL"""
    name = request.args.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)

# ============================================================================
# SQL INJECTION VULNERABILITIES (MEDIUM SEVERITY)
# ============================================================================

def vulnerable_sql_medium_1():
    """ORDER BY clause with concatenation"""
    sort_column = request.args.get("sort", "name")
    query = "ORDER BY " + sort_column

def vulnerable_sql_medium_2():
    """LIMIT clause with concatenation"""
    limit_value = request.form.get("limit", "10")
    query = "LIMIT " + limit_value

def vulnerable_sql_medium_3():
    """SQL comment injection"""
    comment_input = admin_user + "' --"

# ============================================================================
# SQL INJECTION VULNERABILITIES (LOW SEVERITY)
# ============================================================================

def vulnerable_sql_low_1():
    """Simple string concatenation"""
    prefix_name = user_prefix + suffix

def vulnerable_sql_low_2():
    """Basic string building"""
    table_name = "user_" + table_id
