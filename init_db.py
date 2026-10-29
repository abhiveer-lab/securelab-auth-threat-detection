
import sqlite3

con = sqlite3.connect("securelab.db")
cur = con.cursor()

try:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempt_time TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip_address TEXT PRIMARY KEY,
            blocked_until TEXT NOT NULL,
            reason TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_block_history (
            ip_address TEXT PRIMARY KEY,
            block_started_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            description TEXT NOT NULL,
            alert_time TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)

    con.commit()
    print("Database schema initialized successfully.")

except sqlite3.Error:
    con.rollback()
    raise

finally:
    con.close()
