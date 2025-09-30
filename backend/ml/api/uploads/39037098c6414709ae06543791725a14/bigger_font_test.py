# test bigger font size for ML visualization
user_input = input()
cursor.execute("SELECT * FROM users WHERE id = " + user_input)
print("Result:", user_input)
for i in range(10):
    print(i, user_input)
