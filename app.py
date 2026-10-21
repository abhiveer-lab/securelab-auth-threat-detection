import sqlite3
from flask import render_template
from flask import Flask
from flask import request
from werkzeug.security import check_password_hash
from flask import session,redirect,url_for
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key =os.environ["FLASK_SECRET_KEY"]

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = False

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

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
    blocked_until = (
        datetime.now(timezone.utc) + timedelta(minutes=5)
    ).isoformat()

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
        )
    )

    con.commit()
    con.close()

def log_attempt(username, ip_address, status):
    attempt_time = datetime.now(timezone.utc)

    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cur.execute(
        """INSERT INTO auth_logs
           (username, ip_address, attempt_time, status)
           VALUES(?, ?, ?, ?)""",
        (username, ip_address, attempt_time.isoformat(), status)
    )

    con.commit()
    con.close()

def detect_brute_force(ip_address):
    con = sqlite3.connect('securelab.db')
    cur = con.cursor()

    cutoff_time = (
            datetime.now(timezone.utc) - timedelta(minutes=10)
        ).isoformat()
    cur.execute(
        """SELECT COUNT(*)
           FROM auth_logs
           WHERE ip_address = ?
             AND status = 'FAILED'
             AND attempt_time >= ?
             """,
             (ip_address, cutoff_time)
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
    con.close()

    return failed_attempts

@app.route('/login', methods=['POST'])
@app.route('/')
def login():
    if request.method == 'GET':
        return render_template('index.html')

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    error = None

    if not username or not password:
        error = 'Please enter both username and password'
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

    if user is not None and check_password_hash(user[0], password):
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

@app.route('/logout')
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