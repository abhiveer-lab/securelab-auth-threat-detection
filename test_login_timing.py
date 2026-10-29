
import os
import sqlite3
import tempfile
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash
from app import app, detect_brute_force, is_ip_blocked, detect_password_spraying


def setup_test_db(db_path):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=WAL")

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

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_block_history (
            ip_address TEXT PRIMARY KEY,
            block_started_at TEXT NOT NULL
        )
    """)

    cur.execute(
        """
        INSERT INTO users (username, password_hash, role)
        VALUES (?, ?, ?)
        """,
        (
            "testuser",
            generate_password_hash("Correct-Test-Password-123!"),
            "user",
        ),
    )

    con.commit()
    con.close()


with tempfile.TemporaryDirectory() as temp_dir:
    db_path = os.path.join(temp_dir, "test_securelab.db")
    setup_test_db(db_path)

    original_connect = sqlite3.connect

    def test_connect(path, *args, **kwargs):
        if path == "securelab.db":
            path = db_path
        # Give SQLite time to wait for a brief concurrent lock instead of
        # failing immediately. Preserve any timeout explicitly supplied.
        kwargs.setdefault("timeout", 10)
        return original_connect(path, *args, **kwargs)

    sqlite3.connect = test_connect

    try:
        app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
        )

        with app.test_client() as client:

            # 1. Test wrong password for an existing user.
            wrong_password = client.post(
                "/login",
                data={
                    "username": "testuser",
                    "password": "wrong-password",
                },
                environ_overrides={"REMOTE_ADDR": "192.0.2.10"},
            )

            # 2. Test an unknown username.
            unknown_user = client.post(
                "/login",
                data={
                    "username": "no-such-user",
                    "password": "wrong-password",
                },
                environ_overrides={"REMOTE_ADDR": "192.0.2.11"},
            )

            # 3. Test missing credentials.
            missing_credentials = client.post(
                "/login",
                data={
                    "username": "",
                    "password": "",
                },
                environ_overrides={"REMOTE_ADDR": "192.0.2.12"},
            )

            print(
                "Existing username + wrong password:",
                wrong_password.status_code,
            )
            print("Unknown username:", unknown_user.status_code)
            print(
                "Both rejected:",
                wrong_password.status_code == 200
                and unknown_user.status_code == 200,
            )
            print(
                "Missing credentials use generic error:",
                b"Invalid username or password"
                in missing_credentials.data,
            )

            # 4. Test brute-force detection using a dedicated test IP.
            test_ip = "192.0.2.50"

            for attempt in range(1, 6):
                response = client.post(
                    "/login",
                    data={
                        "username": "testuser",
                        "password": "wrong-password",
                    },
                    environ_overrides={"REMOTE_ADDR": test_ip},
                )

                print(
                    f"Brute-force attempt {attempt}:",
                    response.status_code,
                )

                if attempt == 4:
                    con = original_connect(db_path)
                    cur = con.cursor()
                    cur.execute(
                        """
                        SELECT COUNT(*) FROM blocked_ips
                        WHERE ip_address = ?
                        """,
                        (test_ip,),
                    )
                    print(
                        "Blocked after 4 attempts:",
                        cur.fetchone()[0] == 0,
                    )
                    con.close()

            # 5. Verify the fifth attempt created a block.
            con = original_connect(db_path)
            cur = con.cursor()

            cur.execute(
                """
                SELECT COUNT(*) FROM blocked_ips
                WHERE ip_address = ?
                """,
                (test_ip,),
            )
            print(
                "Blocked after 5 attempts:",
                cur.fetchone()[0] == 1,
            )

            # 6. Verify a brute-force alert was created.
            cur.execute(
                """
                SELECT COUNT(*) FROM alerts
                WHERE ip_address = ?
                  AND alert_type = 'BRUTE_FORCE'
                """,
                (test_ip,),
            )
            print(
                "Brute-force alert created:",
                cur.fetchone()[0] == 1,
            )
            con.close()

            # 7. Verify repeated detection does not duplicate alerts.
            detect_brute_force(test_ip)

            con = original_connect(db_path)
            cur = con.cursor()
            cur.execute(
                """
                SELECT COUNT(*) FROM alerts
                WHERE ip_address = ?
                  AND alert_type = 'BRUTE_FORCE'
                """,
                (test_ip,),
            )
            print(
                "Duplicate alert prevented:",
                cur.fetchone()[0] == 1,
            )
            con.close()

            # 8. Check the IP is blocked before testing expiry.
            blocked_response = client.post(
                "/login",
                data={
                    "username": "testuser",
                    "password": "Correct-Test-Password-123!",
                },
                environ_overrides={"REMOTE_ADDR": test_ip},
            )

            print(
                "Blocked IP cannot log in:",
                b"Too many failed login attempts"
                in blocked_response.data,
            )

            # 9. Simulate expiry by setting the block time in the past.
            expired_time = (
                datetime.now(timezone.utc) - timedelta(seconds=1)
            ).isoformat()

            con = original_connect(db_path)
            cur = con.cursor()
            cur.execute(
                """
                UPDATE blocked_ips
                SET blocked_until = ?
                WHERE ip_address = ?
                """,
                (expired_time, test_ip),
            )
            con.commit()
            con.close()

            # 10. Verify the expired block is no longer active.
            print(
                "Expired IP block is no longer active:",
                is_ip_blocked(test_ip) is False,
            )

            # 11. Verify expiry cleanup removed the database entry.
            con = original_connect(db_path)
            cur = con.cursor()
            cur.execute(
                """
                SELECT COUNT(*) FROM blocked_ips
                WHERE ip_address = ?
                """,
                (test_ip,),
            )
            print(
                "Expired block removed from database:",
                cur.fetchone()[0] == 0,
            )
            con.close()

            # 12. Test that one new failure does not immediately re-block an IP after expiry
            retry_response = client.post(
                    "/login",
                    data={
                        "username": "testuser",
                        "password": "Wrong-Password-After-Expiry!",
                    },
                    environ_overrides={"REMOTE_ADDR": test_ip},
                )

            con = original_connect(db_path)
            cur = con.cursor()

            cur.execute(
                """
                SELECT COUNT(*)
                FROM blocked_ips
                WHERE ip_address = ?
                """,
                (test_ip,),
            )

            blocked_again = cur.fetchone()[0] > 0
            con.close()

            print(
                "One new failure does not immediately re-block IP:",
                not blocked_again,
            )

            print(
                "New failure gets normal inavld-credentials response:",
                b"Invalid username or password" in retry_response.data,
            )

            # 13. Test password spraying through the real login route.
            spray_ip = "192.0.2.60"

            for username in ["alice", "bob", "charlie", "david", "eve"]:
                client.post(
                    "/login",
                    data={
                        "username": username,
                        "password": "Wrong-Password-123!",
                    },
                    environ_overrides={"REMOTE_ADDR": spray_ip},
                )

            con = original_connect(db_path)
            cur = con.cursor()

            cur.execute(
                """
                SELECT COUNT(*)
                FROM auth_logs
                WHERE ip_address = ? AND status = 'FAILED'
                """,
                (spray_ip,),
            )
            attempts = cur.fetchone()[0]

            cur.execute(
                """
                SELECT COUNT(DISTINCT username)
                FROM auth_logs
                WHERE ip_address = ? AND status = 'FAILED'
                """,
                (spray_ip,),
            )
            usernames = cur.fetchone()[0]

            cur.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE ip_address = ?
                  AND alert_type = 'PASSWORD_SPRAYING'
                """,
                (spray_ip,),
            )
            spray_alert_count = cur.fetchone()[0]
            con.close()

            print("Route spraying failed attempts:", attempts == 5)
            print("Route spraying distinct usernames:", usernames == 5)
            print(
                "Route created password-spraying alert:",
                spray_alert_count >= 1,
            )

            # 14. Repeated failures against one username should not
            # create a password-spraying alert.
            repeat_ip = "192.0.2.61"

            for _ in range(5):
                client.post(
                    "/login",
                    data={
                        "username": "alice",
                        "password": "Wrong-Password-123!",
                    },
                    environ_overrides={"REMOTE_ADDR": repeat_ip},
                )

            con = original_connect(db_path)
            cur = con.cursor()

            cur.execute(
                """
                SELECT COUNT(DISTINCT username)
                FROM auth_logs
                WHERE ip_address = ? AND status = 'FAILED'
                """,
                (repeat_ip,),
            )
            repeat_usernames = cur.fetchone()[0]

            cur.execute(
                """
                SELECT COUNT(*)
                FROM alerts
                WHERE ip_address = ?
                  AND alert_type = 'PASSWORD_SPRAYING'
                """,
                (repeat_ip,),
            )
            repeat_alert_count = cur.fetchone()[0]
            con.close()

            print("Repeated-user distinct count:", repeat_usernames == 1)
            print(
                "No spraying alert for repeated username:",
                repeat_alert_count == 0,
            )

    finally:
        sqlite3.connect = original_connect
