# SecureLab — Authentication Attack & Defense Lab

SecureLab is an educational Flask-based cybersecurity project that demonstrates authentication security, login monitoring, attack detection, and defensive controls using Python and SQLite.

## Features

- **Password security:** Stores password hashes using Werkzeug.
- **Authentication logging:** Records successful and failed login attempts.
- **Brute-force detection:** Detects repeated failed login attempts from a single IP address.
- **Password-spraying detection:** Detects failed authentication attempts across multiple usernames.
- **Temporary IP blocking:** Blocks suspicious IP addresses for a configured period.
- **Automatic block expiry:** Allows an IP to become eligible for access again after its block expires.
- **Security alerts:** Generates alerts for suspected brute-force and password-spraying activity.
- **Admin dashboard:** Displays authentication logs, alerts, blocked IPs, and login statistics.
- **Failed-login activity chart:** Visualizes failed login activity over a 24-hour period.
- **IP investigation:** Shows authentication history, related alerts, activity summaries, and current block status for an IP address.
- **Role-based access control:** Restricts administrative features to authorized administrators.
- **Alert review and IP management:** Supports reviewing alerts and managing IP blocks.
- **Session security:** Uses Flask sessions with a configured session lifetime and cookie settings.
- **CSRF protection:** Uses Flask-WTF to protect state-changing requests.

## Technology Stack

- Python
- Flask
- SQLite
- Werkzeug
- Flask-WTF
- HTML and CSS

## Project Structure

```text
password-attack-lab/
├── app.py
├── init_db.py
├── create_user.py
├── test_db_cleanup.py
├── test_login_timing.py
├── requirements.txt
├── README.md
├── .env.example
├── templates/
├── static/
└── evidence/
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/abhiveer-lab/securelab-auth-threat-detection.git
cd securelab-auth-threat-detection
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a local `.env` file using `.env.example` as a reference.

Generate a unique secret key for your local environment and set it as `FLASK_SECRET_KEY`. Never commit your real `.env` file or secret key.

### 5. Initialize the database

```bash
python init_db.py
```

Ensure the database schema is initialized before creating users or running the application.

### 6. Create a user

```bash
python create_user.py
```

The script prompts for a username's password and stores its hash. Use it only when creating a new account; it currently specifies `testuser`, so don't rerun it if that username already exists.

Ensure an administrator account is configured with the appropriate role before accessing the admin dashboard.

### 7. Run SecureLab

```bash
python app.py
```

Open `http://127.0.0.1:5000` in your browser.

For local VM testing, configure networking and the Flask listening address appropriately. Do not expose the development server to untrusted networks.

## Security Testing

Test only your own lab or systems for which you have explicit authorization.

Suggested checks include:

- Valid and invalid login attempts
- Admin-page access restrictions for logged-out and normal users
- Brute-force alert generation and temporary IP blocking
- Automatic IP-block expiry
- Password-spraying detection across multiple test accounts
- IP attribution, authentication logs, and investigation details
- CSRF rejection for requests missing a valid token
- Session timeout and logout behavior
- Database query parameterization and secret management

Record the test setup, expected behavior, observed results, and screenshots as evidence.

## Limitations

SecureLab is an educational project, not a production-ready security product. Its detection rules are simplified and may produce false positives or false negatives. Production deployment would require further security review, automated testing, HTTPS configuration, secure cookie settings, operational monitoring, and deployment hardening.

## Future Improvements

- Automated regression tests for authentication, authorization, and detection rules
- Admin audit logging for security-sensitive actions
- More detailed detection analytics and configurable thresholds
- Improved deployment configuration and production security testing

## Author

Developed as a hands-on cybersecurity learning project to explore authentication security, defensive monitoring, and web application security.
