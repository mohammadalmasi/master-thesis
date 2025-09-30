user_input = input(); cursor.execute("SELECT * FROM users WHERE id = " + user_input)
print("Result:", user_input)
for i in range(3):
    print(i)