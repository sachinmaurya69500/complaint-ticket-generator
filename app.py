from datetime import datetime, timedelta
from functools import wraps
import logging
import os
import secrets
import smtplib
from email.message import EmailMessage

from bson import ObjectId
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from pymongo import ASCENDING, MongoClient
from pymongo.errors import PyMongoError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)


def env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = env_bool("SESSION_COOKIE_SECURE", default=False)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "8")))
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", "1048576"))
app.config["STARTUP_CHECK_PASSED"] = False

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

mongo_uri = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
mongo_db_name = os.environ.get("MONGODB_DB", "complaint_ticket_system")
client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
db = client[mongo_db_name]
users_collection = db["users"]
tickets_collection = db["tickets"]


def verify_password(user, password):
    stored_hash = user.get("password_hash")
    if stored_hash:
        return check_password_hash(stored_hash, password)

    # Backward compatibility for older plaintext passwords in existing records.
    legacy_password = user.get("password", "")
    if legacy_password and secrets.compare_digest(legacy_password, password):
        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"password_hash": generate_password_hash(password)}, "$unset": {"password": ""}},
        )
        return True
    return False


def ensure_indexes():
    users_collection.create_index([("email", ASCENDING)], unique=True)
    tickets_collection.create_index([("user_id", ASCENDING), ("created_at", ASCENDING)])


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(24)
        session["csrf_token"] = token
    return token


def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            role = session.get("role")
            if not role:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if role not in allowed_roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("login"))
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": csrf_token}


@app.before_request
def run_startup_once():
    if app.config["STARTUP_CHECK_PASSED"]:
        return
    startup_checks()
    app.config["STARTUP_CHECK_PASSED"] = True


@app.before_request
def enforce_csrf_on_post():
    if request.method != "POST":
        return

    form_token = request.form.get("csrf_token", "")
    session_token = session.get("csrf_token", "")
    if not session_token or not form_token or not secrets.compare_digest(form_token, session_token):
        abort(400, description="Invalid CSRF token")


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.route("/")
def index():
    if session.get("role") == "agent":
        return redirect(url_for("agent_dashboard"))
    if session.get("role") == "customer":
        return redirect(url_for("my_tickets"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for("login"))

        user = users_collection.find_one({"email": email})
        if not user or not verify_password(user, password):
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

        session.permanent = True
        session["user_id"] = str(user["_id"])
        session["role"] = user.get("role", "customer")
        session["email"] = user.get("email")
        flash("Logged in successfully.", "success")

        if session["role"] == "agent":
            return redirect(url_for("agent_dashboard"))
        return redirect(url_for("my_tickets"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/my-tickets", methods=["GET"])
@login_required
@role_required("customer")
def my_tickets():
    tickets = list(tickets_collection.find({"user_id": session["user_id"]}).sort("created_at", -1))
    return render_template("my_tickets.html", tickets=tickets)


@app.route("/create-ticket", methods=["POST"])
@login_required
@role_required("customer")
def create_ticket():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    priority = request.form.get("priority", "Low").strip()

    if not title or not description:
        flash("Title and description are required.", "danger")
        return redirect(url_for("my_tickets"))

    if len(title) > 120:
        flash("Title must be 120 characters or fewer.", "danger")
        return redirect(url_for("my_tickets"))

    if len(description) > 5000:
        flash("Description must be 5000 characters or fewer.", "danger")
        return redirect(url_for("my_tickets"))

    if priority not in ["Low", "Med", "High"]:
        flash("Invalid priority value.", "danger")
        return redirect(url_for("my_tickets"))

    tickets_collection.insert_one(
        {
            "user_id": session["user_id"],
            "title": title,
            "description": description,
            "priority": priority,
            "status": "Open",
            "created_at": datetime.utcnow(),
        }
    )
    flash("Ticket created successfully.", "success")
    return redirect(url_for("my_tickets"))


@app.route("/agent-dashboard", methods=["GET"])
@login_required
@role_required("agent")
def agent_dashboard():
    tickets = list(tickets_collection.find().sort("created_at", -1))
    return render_template("agent_dashboard.html", tickets=tickets)


@app.route("/update-ticket-status/<ticket_id>", methods=["POST"])
@login_required
@role_required("agent")
def update_ticket_status(ticket_id):
    new_status = request.form.get("status", "").strip()

    if new_status not in ["Open", "In Progress", "Closed"]:
        flash("Invalid status value.", "danger")
        return redirect(url_for("agent_dashboard"))

    if not ObjectId.is_valid(ticket_id):
        flash("Invalid ticket ID.", "danger")
        return redirect(url_for("agent_dashboard"))

    tickets_collection.update_one({"_id": ObjectId(ticket_id)}, {"$set": {"status": new_status}})
    flash("Ticket status updated.", "success")
    return redirect(url_for("agent_dashboard"))


@app.route("/delete-ticket/<ticket_id>", methods=["POST"])
@login_required
@role_required("agent")
def delete_ticket(ticket_id):
    if not ObjectId.is_valid(ticket_id):
        flash("Invalid ticket ID.", "danger")
        return redirect(url_for("agent_dashboard"))

    tickets_collection.delete_one({"_id": ObjectId(ticket_id)})
    flash("Ticket deleted.", "success")
    return redirect(url_for("agent_dashboard"))


@app.route("/send-login-email", methods=["POST"])
def send_login_email():
    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Email is required.", "danger")
        return redirect(url_for("login"))

    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_password = os.environ.get("SMTP_PASSWORD")
    sender_email = os.environ.get("SMTP_FROM", smtp_user)

    if not all([smtp_host, smtp_user, smtp_password, sender_email]):
        flash("SMTP is not configured.", "danger")
        return redirect(url_for("login"))

    message = EmailMessage()
    message["Subject"] = "Complaint Ticket System Login"
    message["From"] = sender_email
    message["To"] = email
    message.set_content("Your login request was received. Use your existing password-based login for now.")

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(message)
    except OSError as exc:
        logger.exception("SMTP send failed: %s", exc)
        flash("Unable to send email right now.", "danger")
        return redirect(url_for("login"))

    flash("Login email sent.", "success")
    return redirect(url_for("login"))


@app.route("/healthz", methods=["GET"])
def healthz():
    try:
        client.admin.command("ping")
        return jsonify({"status": "ok", "db": "up"}), 200
    except PyMongoError:
        return jsonify({"status": "degraded", "db": "down"}), 503


@app.errorhandler(400)
def bad_request(error):
    message = getattr(error, "description", "Bad request.")
    return render_template("error.html", code=400, message=message), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The page you requested was not found."), 404


@app.errorhandler(413)
def payload_too_large(_error):
    return render_template("error.html", code=413, message="Uploaded payload is too large."), 413


@app.errorhandler(500)
def server_error(_error):
    return render_template("error.html", code=500, message="Internal server error."), 500


def startup_checks():
    try:
        client.admin.command("ping")
        ensure_indexes()
        logger.info("Connected to MongoDB and indexes ensured")
    except PyMongoError as exc:
        logger.exception("Database startup checks failed: %s", exc)
        raise


if __name__ == "__main__":
    startup_checks()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=env_bool("FLASK_DEBUG", default=False))
