import os
import shutil
import re
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    jsonify,
    g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from config import Config
import database
from logger import security_logger
from validators import (
    validate_filename_and_extension,
    validate_magic_bytes_and_mime,
    generate_secure_storage_name,
    sanitize_and_check_path
)
from scanner import scan_file_with_clamav

def create_app():
    """Application factory for the secure file upload system."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Ensure required application directories exist
    Config.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    Config.TEMP_FOLDER.mkdir(parents=True, exist_ok=True)
    Config.LOGS_FOLDER.mkdir(parents=True, exist_ok=True)

    # Initialize the SQLite database schema
    with app.app_context():
        database.init_db()

    # Teardown database connection after every request
    @app.teardown_appcontext
    def teardown_db(exception):
        database.close_db(exception)

    # ------------------------------------------------------------------
    # Security Middleware: HTTP Headers
    # ------------------------------------------------------------------
    @app.after_request
    def apply_security_headers(response):
        """
        Injects defensive HTTP response headers:
        - X-Content-Type-Options: Prevents browser MIME-sniffing
        - X-Frame-Options: Protects against Clickjacking (DENY)
        - Content-Security-Policy (CSP): Restricts source of executable scripts/styles
        - Referrer-Policy: Protects referrer leakage
        """
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none';"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # ------------------------------------------------------------------
    # Error Handlers
    # ------------------------------------------------------------------
    @app.errorhandler(413)
    def request_entity_too_large(error):
        """Handles file uploads exceeding MAX_CONTENT_LENGTH (10 MB)."""
        client_ip = request.remote_addr
        security_logger.warning(
            f"OVERSIZED FILE UPLOAD DETECTED (> {Config.MAX_CONTENT_LENGTH_MB} MB) from IP: {client_ip}"
        )
        flash(
            f"File is too large! Maximum allowed upload size is {Config.MAX_CONTENT_LENGTH_MB} MB.",
            "danger"
        )
        return redirect(url_for("upload_file")), 413

    # ------------------------------------------------------------------
    # Authentication Guard Decorator
    # ------------------------------------------------------------------
    def login_required(view_func):
        """Enforces authentication check for protected endpoints."""
        @wraps(view_func)
        def decorated_view(*args, **kwargs):
            if "user_id" not in session:
                flash("Authentication required. Please log in to continue.", "warning")
                return redirect(url_for("login", next=request.url))
            return view_func(*args, **kwargs)
        return decorated_view

    # ------------------------------------------------------------------
    # Core Public Routes
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        """Home page with project overview."""
        return render_template("index.html")

    @app.route("/health")
    def health():
        """Health check endpoint."""
        return jsonify({
            "status": "healthy",
            "service": "Secure File Upload & Malware Detection System"
        }), 200

    # ------------------------------------------------------------------
    # Authentication Routes
    # ------------------------------------------------------------------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        """Registers a new user with securely hashed credentials."""
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            client_ip = request.remote_addr

            # Input validation
            if not username or not email or not password:
                flash("All fields are required.", "danger")
                return render_template("register.html", username=username, email=email)

            if not re.match(r"^[a-zA-Z0-9_-]{3,30}$", username):
                flash("Username must be 3-30 alphanumeric characters, underscores, or hyphens.", "danger")
                return render_template("register.html", username=username, email=email)

            if "@" not in email or "." not in email:
                flash("Please enter a valid email address.", "danger")
                return render_template("register.html", username=username, email=email)

            if len(password) < 8:
                flash("Password must be at least 8 characters in length.", "danger")
                return render_template("register.html", username=username, email=email)

            if password != confirm_password:
                flash("Passwords do not match.", "danger")
                return render_template("register.html", username=username, email=email)

            # Check if user or email already exists
            if database.get_user_by_username(username):
                flash("Username is already taken. Please choose another.", "danger")
                return render_template("register.html", username=username, email=email)

            if database.get_user_by_email(email):
                flash("Email is already registered. Please login.", "danger")
                return render_template("register.html", username=username, email=email)

            # Hash the password securely using Werkzeug's modern scrypt/pbkdf2
            # Salts are generated automatically and embedded in the hash
            password_hash = generate_password_hash(password)

            # Save user in database
            user_id = database.create_user(username, email, password_hash)
            security_logger.info(f"USER REGISTERED: username='{username}', id={user_id}, ip={client_ip}")

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Authenticates users and establishes a secure session."""
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            client_ip = request.remote_addr

            user = database.get_user_by_username(username)

            # Timing-attack resistant verification with check_password_hash
            if user and check_password_hash(user["password_hash"], password):
                # Successful authentication
                session.clear()  # Mitigate session fixation by resetting previous session
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                security_logger.info(f"LOGIN SUCCESS: user='{username}', ip={client_ip}")
                flash(f"Welcome back, {user['username']}!", "success")

                # Handle optional redirect parameter
                next_url = request.args.get("next")
                if next_url and next_url.startswith("/"):
                    return redirect(next_url)
                return redirect(url_for("dashboard"))
            else:
                # Authentication failure: Use generic error message to prevent user enumeration
                security_logger.warning(f"LOGIN FAILED: username='{username}', ip={client_ip}")
                flash("Invalid username or password.", "danger")
                return render_template("login.html", username=username)

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        """Terminates user session."""
        username = session.get("username", "anonymous")
        security_logger.info(f"LOGOUT: user='{username}', ip={request.remote_addr}")
        session.clear()
        flash("You have been successfully logged out.", "info")
        return redirect(url_for("index"))

    # ------------------------------------------------------------------
    # Protected Application Routes
    # ------------------------------------------------------------------
    @app.route("/dashboard")
    @login_required
    def dashboard():
        """Displays all uploaded and scanned files owned by the logged-in user."""
        user_id = session["user_id"]
        files = database.get_user_files(user_id)
        return render_template("dashboard.html", files=files)

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload_file():
        """
        Multi-layer secure file upload handler:
        1. Checks file presence
        2. Validates filename & checks for dangerous/double extensions
        3. Inspects binary magic bytes to defeat MIME spoofing
        4. Generates random UUID storage filename (prevents path traversal & overwrites)
        5. Stages file in quarantine (temp_uploads/)
        6. Scans with ClamAV:
           - Malicious -> Permanently deleted & alert logged
           - Clean -> Moved to permanent uploads/ & recorded in DB
           - Scanner Unavailable -> Stored, marked as unverified, user alerted
        """
        if request.method == "POST":
            user_id = session["user_id"]
            client_ip = request.remote_addr

            # Helper to return either JSON or standard redirect based on request type
            is_ajax = (
                request.headers.get("X-Requested-With") == "XMLHttpRequest" or
                "application/json" in request.headers.get("Accept", "")
            )

            # Step 1: Ensure file was submitted
            if "file" not in request.files:
                err = "No file part provided in upload form."
                if is_ajax:
                    return jsonify({"success": False, "error": err}), 400
                flash(err, "warning")
                return redirect(request.url)

            file = request.files["file"]
            if not file or file.filename == "":
                err = "No file was selected for upload."
                if is_ajax:
                    return jsonify({"success": False, "error": err}), 400
                flash(err, "warning")
                return redirect(request.url)

            raw_original_name = file.filename
            security_logger.info(
                f"UPLOAD ATTEMPT: User {user_id} submitted '{raw_original_name}' from IP {client_ip}"
            )

            # Step 2: Validate extension and check for dangerous / double extensions
            valid_ext, ext_error, declared_ext = validate_filename_and_extension(raw_original_name)
            if not valid_ext:
                if is_ajax:
                    return jsonify({"success": False, "error": ext_error}), 400
                flash(ext_error, "danger")
                return redirect(request.url)

            # Step 3: Inspect binary magic bytes & MIME type
            valid_mime, mime_error, detected_mime = validate_magic_bytes_and_mime(file.stream, declared_ext)
            if not valid_mime:
                if is_ajax:
                    return jsonify({"success": False, "error": mime_error}), 400
                flash(mime_error, "danger")
                return redirect(request.url)

            # Step 4: Generate a random UUIDv4 storage filename
            # Original filename is discarded for storage to prevent path traversal
            stored_filename = generate_secure_storage_name(declared_ext)
            
            # Step 5: Save to quarantine temporary staging directory first
            temp_path = Config.TEMP_FOLDER / stored_filename
            file.save(str(temp_path))

            # Step 6: Antivirus scan with ClamAV
            scan_status, scan_detail = scan_file_with_clamav(temp_path)

            if scan_status == "malicious":
                # Threat detected! Destroy the file from disk immediately
                try:
                    if temp_path.exists():
                        temp_path.unlink()
                except Exception as e:
                    security_logger.error(f"Error purging malicious file: {e}")

                alert_msg = f"SECURITY ALERT: Malware detected! [{scan_detail}]. The file was rejected and immediately destroyed."
                if is_ajax:
                    return jsonify({
                        "success": False,
                        "error": alert_msg,
                        "scan_status": "malicious",
                        "scan_detail": scan_detail
                    }), 400

                flash(alert_msg, "danger")
                return redirect(url_for("upload_file"))

            # Clean or scanner_unavailable: Move from quarantine to permanent storage
            final_path = Config.UPLOAD_FOLDER / stored_filename
            shutil.move(str(temp_path), str(final_path))
            file_size = final_path.stat().st_size

            # Store sanitized metadata in SQLite
            database.create_file_record(
                user_id=user_id,
                original_filename=secure_filename(raw_original_name) or "unnamed_file",
                stored_filename=stored_filename,
                file_size=file_size,
                file_type=detected_mime,
                scan_status=scan_status,
                scan_result=scan_detail
            )

            if scan_status == "clean":
                msg = f"File '{secure_filename(raw_original_name)}' was scanned clean and stored securely."
                cat = "success"
            else:
                # scanner_unavailable
                msg = "File stored, BUT ClamAV malware scanner is offline/unavailable. File could not be verified for malware."
                cat = "warning"

            if is_ajax:
                return jsonify({
                    "success": True,
                    "message": msg,
                    "scan_status": scan_status,
                    "scan_detail": scan_detail,
                    "redirect_url": url_for("dashboard")
                }), 200

            flash(msg, cat)
            return redirect(url_for("dashboard"))

        return render_template("upload.html")

    @app.route("/download/<int:file_id>")
    @login_required
    def download_file(file_id):
        """
        Secure file download handler:
        - Authenticates user
        - Enforces strict authorization (Owner check: file.user_id == session.user_id)
        - Prevents IDOR (Insecure Direct Object Reference)
        - Serves file via send_from_directory without exposing server directory paths
        """
        user_id = session["user_id"]
        client_ip = request.remote_addr

        file_record = database.get_file_by_id(file_id)
        if not file_record:
            flash("The requested file was not found.", "danger")
            return redirect(url_for("dashboard"))

        # AUTHORIZATION CHECK: Prevent IDOR
        if file_record["user_id"] != user_id:
            security_logger.warning(
                f"UNAUTHORIZED DOWNLOAD ATTEMPT (IDOR): User ID {user_id} attempted to access "
                f"File ID {file_id} (belonging to User ID {file_record['user_id']}) from IP {client_ip}"
            )
            flash("Access denied: You do not have authorization to access this file.", "danger")
            return redirect(url_for("dashboard")), 403

        # Prevent downloading quarantined or malicious files
        if file_record["scan_status"] == "malicious":
            flash("Access denied: This file was flagged as malicious.", "danger")
            return redirect(url_for("dashboard")), 403

        # Verify file exists on disk
        stored_path = Config.UPLOAD_FOLDER / file_record["stored_filename"]
        if not stored_path.exists():
            flash("Error: File payload missing from secure vault storage.", "danger")
            return redirect(url_for("dashboard"))

        security_logger.info(
            f"FILE DOWNLOAD: User {user_id} downloaded File ID {file_id} "
            f"('{file_record['original_filename']}') from IP {client_ip}"
        )

        return send_from_directory(
            directory=Config.UPLOAD_FOLDER,
            path=file_record["stored_filename"],
            as_attachment=True,
            download_name=file_record["original_filename"]
        )

    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
