import sqlite3
from werkzeug.security import generate_password_hash
from getpass import getpass

username = "testuser"
password = getpass("Enter password for new user: ")

password_hash = generate_password_hash(password)
con = sqlite3.connect('securelab.db')
cur = con.cursor()

cur.execute(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
     (username, password_hash)
)

con.commit()
con.close()

print("Test user create successfully")
