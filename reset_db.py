import os

db_file = "users.db"
if os.path.exists(db_file):
    os.remove(db_file)
    print(f"Deleted {db_file}")
else:
    print(f"{db_file} not found")

print("\nNow restart your backend server.")
print("The database will be recreated with the new schema.")
