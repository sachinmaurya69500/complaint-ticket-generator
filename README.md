# Complaint Ticket Generator

A production-ready Flask + MongoDB complaint ticket system with:

- Role-based access (`customer` and `agent`)
- Secure sessions and CSRF protection on all POST forms
- Password hash support with automatic migration from legacy plaintext password records
- Health check endpoint for deployment monitoring
- Gunicorn support for deployment

## Features

- Customer login and ticket creation
- Customer view for personal tickets
- Agent dashboard to update status and delete tickets
- SMTP "send login email" utility
- Error pages for 400/404/413/500 responses

## Tech Stack

- Python 3.11+
- Flask 3
- PyMongo
- Gunicorn (production web server)
- MongoDB

## Local Setup

1. Create and activate a virtual environment.
2. Install dependencies.
3. Configure environment variables.
4. Run the app.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

App runs at `http://localhost:5000`.

## Environment Variables

Use `.env.example` as reference.

- `SECRET_KEY`: long random secret (required in production)
- `FLASK_DEBUG`: `true`/`false`
- `PORT`: server port (default `5000`)
- `MONGODB_URI`: Mongo connection string
- `MONGODB_DB`: database name
- `SESSION_COOKIE_SECURE`: set `true` behind HTTPS in production
- `SESSION_LIFETIME_HOURS`: login session lifetime
- `MAX_CONTENT_LENGTH`: max request payload size in bytes
- `LOG_LEVEL`: e.g. `INFO`, `DEBUG`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`: optional SMTP config

## Data Model

### users

- `email` (unique, indexed)
- `role` (`customer` or `agent`)
- `password_hash` (recommended)
- `password` (legacy only; auto-migrated to hash on successful login)

### tickets

- `user_id`
- `title`
- `description`
- `priority` (`Low`, `Med`, `High`)
- `status` (`Open`, `In Progress`, `Closed`)
- `created_at`

## Production Run (Gunicorn)

```bash
gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --threads 4 --timeout 60 app:app
```

## Deploy Notes

- Configure all environment variables from `.env.example`.
- Use a managed MongoDB (for example MongoDB Atlas) and allow network access from your host.
- Keep `SESSION_COOKIE_SECURE=true` on HTTPS deployments.
- Use `/healthz` for readiness checks.

## Security Notes

- Passwords are verified using hashes when `password_hash` exists.
- Legacy plaintext password field is automatically migrated to hash after successful login.
- CSRF token is required for all POST routes.
- Basic secure response headers are added for all responses.

## License

Add your preferred license before public release.