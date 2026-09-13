import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file if present
load_dotenv(BASE_DIR / ".env")

class Config:
    """Application Configuration with secure defaults."""
    
    BASE_DIR = BASE_DIR
    
    # Secret key for session management and CSRF protection
    # Falls back to a default only in development; never use default in production
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-fallback-key-replace-with-secrets-token-hex")
    
    # 10 MB Maximum upload size to protect against Oversized File Upload (DoS)
    MAX_CONTENT_LENGTH_MB = int(os.getenv("MAX_CONTENT_LENGTH_MB", 10))
    MAX_CONTENT_LENGTH = MAX_CONTENT_LENGTH_MB * 1024 * 1024
    
    # Storage paths (kept completely outside the static/ directory)
    UPLOAD_FOLDER = BASE_DIR / "uploads"
    TEMP_FOLDER = BASE_DIR / "temp_uploads"
    LOGS_FOLDER = BASE_DIR / "logs"
    DATABASE_PATH = BASE_DIR / "database.db"
    SECURITY_LOG_PATH = LOGS_FOLDER / "security.log"
    
    # ClamAV settings
    CLAMSCAN_PATH = os.getenv("CLAMSCAN_PATH", r"C:\Program Files\ClamAV\clamscan.exe")
    CLAMD_HOST = os.getenv("CLAMD_HOST", "127.0.0.1")
    CLAMD_PORT = int(os.getenv("CLAMD_PORT", 3310))
    
    # Whitelisted file extensions (strictly enforced)
    ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png", "docx"}
    
    # Dangerous extensions explicitly blocked and alerted
    DANGEROUS_EXTENSIONS = {
        "exe", "bat", "cmd", "sh", "php", "php3", "php4", "php5", "phtml",
        "js", "html", "htm", "dll", "msi", "vbs", "ps1", "jar", "war", "py", "pl"
    }
    
    # MIME-type mapping for legitimate file types
    ALLOWED_MIME_TYPES = {
        "pdf": ["application/pdf"],
        "jpg": ["image/jpeg"],
        "jpeg": ["image/jpeg"],
        "png": ["image/png"],
        "docx": [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip"  # docx files are zip archives under the hood
        ]
    }
    
    # Cookie security settings
    SESSION_COOKIE_HTTPONLY = True        # Prevents client-side scripts from reading session cookie (mitigates XSS cookie theft)
    SESSION_COOKIE_SAMESITE = "Lax"       # Helps mitigate Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SECURE = False         # Set to True when HTTPS/TLS is configured
