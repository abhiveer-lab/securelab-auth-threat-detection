import sqlite3
from flask import render_template
from flask import Flask
from flask import request
from werkzeug.security import check_password_hash
from flask import session,redirect,url_for
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

load_dotenv()

app = Flask(__name__)
app.secret_key =os.environ["FLASK_SECRET_KEY"]

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = False

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

csrf = CSRFProtect(app)

DUMMY_PASSWORD_HASH = "scrypt:32768:8:1$hYL8oJJUi7cplDXn$9b6b1b0a3723ef69969bc1bdb769ea5d0ddb73f6346714b7fe0f6a4a4ef90a758c4d6023edd897b120ea45425210036db74b9cc017b3e0e1844fb22445037e78"

def is_ip_blocked(ip_address):
    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        "SELECT blocked_until FROM blocked_ips WHERE ip_address =?",
        (ip_address,)
    )

    row = cur.fetchone()
    con.close()

    if row is None:
        return False

    blocked_until = datetime.fromisoformat(row[0])
    now = datetime.now(timezone.utc)

    if now < blocked_until:
        return True

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()
    cur.execute(
        "DELETE FROM blocked_ips WHERE ip_address = ?",
        (ip_address, )
    )

    con.commit()
    con.close()

    return False

def block_ip(ip_address):
    now = datetime.now(timezone.utc)
    block_started_at = now.isoformat()
    blocked_until = (now + timedelta(minutes=5)).isoformat()

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        """INSERT OR REPLACE INTO blocked_ips
           (ip_address, blocked_until, reason)
           VALUES(?, ?, ?)""",
        (
            ip_address,
            blocked_until,
            'Five failed login attempts within 10 minutes'
        ),
    )

    cur.execute(
        """
        INSERT OR REPLACE INTO ip_block_history
            (ip_address, block_started_at)
        VALUES (?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET block_started_at = excluded.block_started_at """,
        (ip_address, block_started_at),
    )

    con.commit()
    con.close()

def log_attempt(username, ip_address, status):
    attempt_time = datetime.now(timezone.utc)

    con = sqlite3.connect('securelab.db')
    try:
        cur = con.cursor()

        cur.execute(
            """INSERT INTO auth_logs
            (username, ip_address, attempt_time, status)
            VALUES(?, ?, ?, ?)""",
            (username, ip_address, attempt_time.isoformat(), status)
        )

        con.commit()

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

def detect_brute_force(ip_address):
    con = sqlite3.connect('securelab.db')

    try:
        cur = con.cursor()

        now = datetime.now(timezone.utc)
        cutoff_time = (now - timedelta(minutes=10)).isoformat()

        cur.execute(
            """
            SELECT block_started_at FROM ip_block_history WHERE ip_Address = ?
            """,
            (ip_address, ),
        )

        block_row = cur.fetchone()

        if block_row is not None:
            cur.execute(
                """SELECT COUNT(*)
                FROM auth_logs
                WHERE ip_address = ?
                    AND status = 'FAILED'
                    AND attempt_time >= ?
                    AND attempt_time > ?
                    """,
                    (ip_address, cutoff_time, block_row[0]),
            )

        else:
            cur.execute(
                """
                SELECT COUNT(*)
                FROM auth_logs
                WHERE ip_address = ?
                AND status = 'FAILED'
                AND attempt_time >= ?
                """,
                (ip_address, cutoff_time),
            )

        failed_attempts = cur.fetchone()[0]

        if failed_attempts >= 5:
            cur.execute(
                """SELECT id FROM alerts
                    WHERE ip_address = ?
                    AND alert_type = 'BRUTE_FORCE'
                    AND alert_time >= ?
                    """,
                    (ip_address, cutoff_time)
            )

            if cur.fetchone() is None:
                cur.execute(
                    """INSERT INTO alerts
                    (ip_address, alert_type, description, alert_time, status)
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        ip_address,
                        'BRUTE_FORCE',
                        'Five or more failed login attempts within 10 minutes',
                        datetime.now(timezone.utc).isoformat(),
                        'NEW'
                    )
                )

        con.commit()
        return failed_attempts

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

def detect_password_spraying(ip_address):
    con = sqlite3.connect('securelab.db')

    try:
        cur = con.cursor()

        cutoff_time = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()

        cur.execute(
            """
            SELECT COUNT(*), COUNT(DISTINCT username)
            FROM auth_logs
            WHERE ip_address = ?
            AND status = 'FAILED'
            AND attempt_time >= ?
            """,
            (ip_address, cutoff_time)
        )

        row = cur.fetchone()

        if row is None:
            failed_attempts = 0
            distinct_usernames = 0
        else:
            failed_attempts, distinct_usernames = row

        if failed_attempts >= 5 and distinct_usernames >= 5:
            cur.execute(
                """
                SELECT id FROM alerts
                WHERE ip_address = ?
                AND alert_type = 'PASSWORD_SPRAYING'
                AND alert_time >= ?
                """,
                (ip_address, cutoff_time)
            )

            if cur.fetchone() is None:
                cur.execute(
                    """
                    INSERT INTO alerts
                        (ip_address, alert_type, description, alert_time, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        ip_address,
                        'PASSWORD_SPRAYING',
                        'Failed login attempts against five or more usernames within 10 minutes',
                        datetime.now(timezone.utc).isoformat(),
                        'NEW'
                    )
                )

        con.commit()
        return failed_attempts, distinct_usernames

    except Exception:
        con.rollback()
        raise

    finally:
        con.close()

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('index.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    error = None

    if not username or not password:
        error = 'Invalid username or password'
        return render_template('index.html', error=error)

    ip_address = request.remote_addr

    if is_ip_blocked(ip_address):
        error = 'Too many failed login attempts. Try again in 5 minutes.'
        return render_template('index.html', error=error)

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        "SELECT password_hash, role FROM users WHERE username = ?",
        (username,)
    )

    user = cur.fetchone()
    con.close()

    password_hash = user[0] if user is not None else DUMMY_PASSWORD_HASH
    password_valid = check_password_hash(password_hash, password)

    if user is not None and password_valid:
        log_attempt(username, ip_address, 'SUCCESS')

        session.clear()
        session.permanent = True
        session['username'] = username
        session['role'] = user[1]

        if user[1] == 'admin':
            return redirect(url_for('dashboard'))

        return 'Login successful'

    log_attempt(username, ip_address, 'FAILED')

    failed_attempts = detect_brute_force(ip_address)
    detect_password_spraying(ip_address)
    if failed_attempts >= 5:
        block_ip(ip_address)
        error = 'Too many failed login attempts. Try again in 5 minutes.'
    else:
        error = 'Invalid username or password'

    return render_template('index.html', error=error)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return 'Access denied', 403

    username = session['username']

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        "SELECT role FROM users WHERE username = ?",
        (username, )
    )

    user = cur.fetchone()
    con.close()

    if user is None or user[0] != 'admin':
        return 'Access denied', 403

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        """SELECT username, ip_address, attempt_time,status FROM auth_logs ORDER BY id DESC"""
    )
    logs = cur.fetchall()

    cur.execute(
        """SELECT id, ip_address, alert_type, description, alert_time, status FROM alerts
        ORDER BY id DESC"""
    )

    alerts = cur.fetchall()

    cur.execute(
        """SELECT ip_address, blocked_until, reason FROM  blocked_ips
        ORDER BY blocked_until DESC"""
    )

    blocked_ips = cur.fetchall()

    cur.execute(
        """SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END)
            FROM auth_logs"""
    )

    stats = cur.fetchone()
    con.close()

    total_events = stats[0] or 0
    successful_logins = stats[1] or 0
    failed_logins = stats[2] or 0

    current_time = datetime.now(timezone.utc).isoformat()

    return render_template(
        'dashboard.html',
        logs=logs,
        total_events=total_events,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        alerts=alerts,
        blocked_ips=blocked_ips,
        current_time=current_time
    )

@app.route('/alerts/<int:alert_id>/review', methods=['POST'])
def review_alert(alert_id):
    #check whether someone is logged in
    if 'username' not in session:
        return 'Access denied', 403

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    #verify the user's current role from the database
    cur.execute(
        "SELECT role FROM users WHERE username = ?",
        (session['username'],)
    )

    user = cur.fetchone()

    if user is None or user[0] != 'admin':
        con.close()
        return 'Access denied', 403

    #change a new alert to REVIEWED
    cur.execute(
        """UPDATE alerts
           SET status = 'REVIEWED'
           WHERE id = ? AND status ='NEW'""",
        (alert_id,)
    )

    con.commit()
    con.close()

    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/unblock/<ip_address>', methods=['POST'])
def unblock_ip(ip_address):
    if 'username' not in session:
        return 'Access denied', 403

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        "SELECT role FROM users WHERE username = ?",
        (session['username'],)
    )

    user = cur.fetchone()

    if user is None or user[0] != 'admin':
        con.close()
        return 'Access denied', 403

    cur.execute(
        "DELETE FROM blocked_ips WHERE ip_address= ?",
        (ip_address, )
    )

    con.commit()
    con.close()

    return redirect(url_for('dashboard'))

if __name__ == "__main__":
    app.run(debug=False)