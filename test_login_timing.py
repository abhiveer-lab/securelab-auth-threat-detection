
import sqlite3
import tempfile
import os

from flask import g
from werkzeug.security import generate_password_hash
from app import app, DUMMY_PASSWORD_HASH


def setup_test_db(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempt_time TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE blocked_ips (
            ip_address TEXT PRIMARY KEY,
            blocked_until TEXT NOT NULL,
            reason TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            description TEXT NOT NULL,
            alert_time TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cur.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("testuser", generate_password_hash("Correct-Test-Password-123!"), "user")
    )

    con.commit()
    con.close()


with tempfile.TemporaryDirectory() as temp_dir:
    db_path = os.path.join(temp_dir, "test_securelab.db")
    setup_test_db(db_path)

    # Redirect app database connections to the isolated test database.
    import app as securelab

    original_connect = sqlite3.connect

    def test_connect(path, *args, **kwargs):
        if path == "securelab.db":
            path = db_path
        return original_connect(path, *args, **kwargs)

    sqlite3.connect = test_connect

    try:
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)

        with app.test_client() as client:
            wrong_password = client.post(
                "/login",
                data={"username": "testuser", "password": "wrong-password"},
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"}
            )

            unknown_user = client.post(
                "/login",
                data={"username": "no-such-user", "password": "wrong-password"},
                environ_overrides={"REMOTE_ADDR": "192.0.2.11"}
            )

            print("Existing username + wrong password:", wrong_password.status_code)
            print("Unknown username:", unknown_user.status_code)
            print("Both rejected:", wrong_password.status_code == 200 and unknown_user.status_code == 200)

    finally:
        sqlite3.connect = original_connect
