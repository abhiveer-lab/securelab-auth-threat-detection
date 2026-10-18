# SecureLab — Authentication Attack & Defense Lab

A Flask-based cybersecurity project that demonstrates secure authentication, login monitoring, brute-force detection, and defensive controls using Python and SQLite.

## Features

- **Password security:** Passwords are hashed using Werkzeug.
- **Authentication logging:** Records successful and failed login attempts.
- **Brute-force detection:** Detects repeated failed login attempts from the same IP address.
- **Temporary IP blocking:** Temporarily blocks an IP after repeated failures.
- **Security alerts:** Generates alerts for suspected brute-force activity.
- **Admin dashboard:** Displays authentication logs, alerts, and login statistics.
- **Access control:** Restricts administrative features to authorized administrators.
- **Alert review:** Allows administrators to mark alerts as reviewed.

## Technology Stack

- Python
- Flask
- SQLite
- HTML and CSS
- Werkzeug password hashing

## Project Structure

```text
password-attack-lab/
├── app.py
├── init_db.py
├── create_user.py
├── templates/
│   ├── index.html
│   └── dashboard.html
├── static/
│   ├── style.css
│   └── dashboard.css
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/abhiveer-lab/securelab-auth-threat-detection.git
cd securelab-auth-threat-detection
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

Install the packages listed in `requirements.txt`.

### 4. Configure the application

Create a local `.env` file using `.env.example` as a reference. Generate a unique random Flask secret key for your local environment. Never commit your real `.env` file.

### 5. Initialize the database

```bash
python init_db.py
```

Ensure the application's required database tables are initialized before running it.

### 6. Start the application

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## Security Testing

Use only your own local instance or an environment where you have explicit authorization.

Suggested tests include:

- Valid and invalid login attempts
- Access to the admin dashboard as a regular user
- Repeated failed login attempts and alert generation
- Temporary IP block expiry
- Alert review authorization
- Logout and session protection

## Limitations

This is an educational project and is not yet intended for production deployment. Production use would require additional security hardening, testing, and deployment configuration.

## Future Improvements

- Blocked IP management in the admin dashboard
- Automated authentication and authorization tests
- Admin audit logging
- CSRF protection and secure cookie configuration
- Security analytics and visualizations

## Author

Developed as a hands-on cybersecurity learning project to explore authentication security, defensive monitoring, and web application security.
