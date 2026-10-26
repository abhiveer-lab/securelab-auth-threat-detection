import sqlite3

con = sqlite3.connect('securelab.db')
cur = con.cursor()

cur.execute("""
    CREATE TABLE IF NOT  EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
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

con.commit()
con.close()

print("Database tables checked successfully")
print("Rate-limiting and block-history tables are ready")
