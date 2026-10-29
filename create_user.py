import sqlite3
from getpass import getpass
from werkzeug.security import generate_password_hash

DB_PATH = "securelab.db"
VALID_ROLES = {"user", "admin"}


def create_user():
    username = input("Enter username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    role = input("Enter role (user/admin): ").strip().lower()

    if role not in VALID_ROLES:
        print("Invalid role. Choose 'user' or 'admin'.")
        return

    password = getpass("Enter password: ")
    confirm_password = getpass("Confirm password: ")

    if len(password) < 12:
        print("Password must be at least 12 characters.")
        return

    if password != confirm_password:
        print("Passwords do not match.")
        return

    password_hash = generate_password_hash(password)

    con = sqlite3.connect(DB_PATH)

    try:
        con.execute(
            """
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, role),
        )
        con.commit()
        print(f"User '{username}' created successfully with role '{role}'.")

    except sqlite3.IntegrityError:
        con.rollback()
        print("That username already exists.")

    finally:
        con.close()


if __name__ == "__main__":
    create_user()
