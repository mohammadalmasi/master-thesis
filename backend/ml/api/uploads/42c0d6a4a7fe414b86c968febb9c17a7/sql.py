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