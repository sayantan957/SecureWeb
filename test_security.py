import io
import os
import unittest
from pathlib import Path
from app import create_app
import database
from config import Config

class SecurityTestSuite(unittest.TestCase):
    """
    Comprehensive Security Verification Test Suite
    Covers all 10 core threats and verifies defensive controls.
    """

    @classmethod
    def setUpClass(cls):
        """Set up test environment and isolate test database."""
        # Use an in-memory or dedicated test database
        cls.test_db_path = Config.BASE_DIR / "test_security.db"
        Config.DATABASE_PATH = cls.test_db_path
        
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls):
        """Clean up test database and any leftover files."""
        if cls.test_db_path.exists():
            try:
                cls.test_db_path.unlink()
            except Exception:
                pass

    def setUp(self):
        """Initialize database before each test run."""
        with self.app.app_context():
            database.init_db()

    # ------------------------------------------------------------------
    # 1. User Authentication & Password Hashing Verification
    # ------------------------------------------------------------------
    def test_01_user_registration_and_password_hashing(self):
        """Verify user registration and verify password is NEVER stored in plaintext."""
        response = self.client.post("/register", data={
            "username": "alice",
            "email": "alice@college.edu",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        with self.app.app_context():
            user = database.get_user_by_username("alice")
            self.assertIsNotNone(user)
            # Verify password is NOT plaintext
            self.assertNotEqual(user["password_hash"], "SecurePassword123!")
            # Verify hash prefix (scrypt or pbkdf2)
            self.assertTrue(
                user["password_hash"].startswith("scrypt:") or 
                user["password_hash"].startswith("pbkdf2:")
            )

    def test_02_authentication_and_session(self):
        """Verify valid and invalid login attempts."""
        # Failed login attempt
        bad_login = self.client.post("/login", data={
            "username": "alice",
            "password": "WrongPassword!"
        }, follow_redirects=True)
        self.assertIn(b"Invalid username or password", bad_login.data)

        # Successful login
        good_login = self.client.post("/login", data={
            "username": "alice",
            "password": "SecurePassword123!"
        }, follow_redirects=True)
        self.assertEqual(good_login.status_code, 200)
        self.assertIn(b"Welcome back, alice!", good_login.data)

    # ------------------------------------------------------------------
    # 2. File Upload Tests (Valid & Attack Vectors)
    # ------------------------------------------------------------------
    def login_as_alice(self):
        return self.client.post("/login", data={
            "username": "alice",
            "password": "SecurePassword123!"
        }, follow_redirects=True)

    def test_03_valid_pdf_upload(self):
        """Verify that a legitimate PDF with valid magic bytes (%PDF-) is accepted."""
        self.login_as_alice()
        valid_pdf_content = b"%PDF-1.4\n%Fake PDF content for test\n%%EOF"
        data = {
            "file": (io.BytesIO(valid_pdf_content), "report.pdf")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        # Should be accepted and stored
        self.assertTrue(
            b"scanned clean and stored securely" in response.data or
            b"File stored, BUT ClamAV malware scanner is offline" in response.data
        )

    def test_04_valid_jpg_upload(self):
        """Verify that a legitimate JPEG with valid magic bytes (\xff\xd8\xff) is accepted."""
        self.login_as_alice()
        valid_jpg_content = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x60\x00\x60\x00\x00\xff\xdb"
        data = {
            "file": (io.BytesIO(valid_jpg_content), "photo.jpg")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            b"scanned clean and stored securely" in response.data or
            b"File stored, BUT ClamAV malware scanner is offline" in response.data
        )

    def test_05_reject_dangerous_exe(self):
        """Verify that executable files (.exe) are strictly rejected."""
        self.login_as_alice()
        data = {
            "file": (io.BytesIO(b"MZ\x90\x00...fake exe payload"), "malware.exe")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Dangerous file type detected", response.data)

    def test_06_reject_dangerous_php(self):
        """Verify that PHP script files (.php) are strictly rejected."""
        self.login_as_alice()
        data = {
            "file": (io.BytesIO(b"<?php phpinfo(); ?>"), "shell.php")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Dangerous file type detected", response.data)

    def test_07_reject_dangerous_js(self):
        """Verify that JavaScript files (.js) are strictly rejected."""
        self.login_as_alice()
        data = {
            "file": (io.BytesIO(b"alert('XSS');"), "evil.js")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Dangerous file type detected", response.data)

    def test_08_reject_double_extension_attack(self):
        """Verify that double-extension bypass attempts (e.g. payload.php.jpg) are blocked."""
        self.login_as_alice()
        data = {
            "file": (io.BytesIO(b"\xff\xd8\xfffake jpeg with php"), "shell.php.jpg")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Dangerous file type detected", response.data)

    def test_09_detect_mime_type_spoofing(self):
        """
        Verify MIME spoofing defense: A PHP script renamed to photo.jpg
        without genuine JPEG magic bytes must be caught and rejected.
        """
        self.login_as_alice()
        spoofed_content = b"<?php system($_GET['cmd']); ?>"
        data = {
            "file": (io.BytesIO(spoofed_content), "photo.jpg")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"File content verification failed", response.data)

    def test_10_eicar_malware_detection(self):
        """
        Verify that harmless standard EICAR test string is detected as malware
        and immediately purged from disk without being saved to the vault.
        """
        self.login_as_alice()
        # Official EICAR standard antivirus test string (harmless 68-byte ASCII)
        eicar_string = b"%PDF-1.4\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        data = {
            "file": (io.BytesIO(eicar_string), "test_malware.pdf")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertIn(b"Malware detected", response.data)

    def test_11_path_traversal_prevention(self):
        """
        Verify path traversal attempt (e.g. ../../app.py) does NOT escape
        storage directories and original filename is never used directly as disk path.
        """
        self.login_as_alice()
        valid_pdf_content = b"%PDF-1.4\nSafe PDF content\n%%EOF"
        data = {
            "file": (io.BytesIO(valid_pdf_content), "../../../evil.pdf")
        }
        response = self.client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # Check database: stored filename must be a UUID, not ../../../evil.pdf
        with self.app.app_context():
            files = database.get_user_files(1)
            latest = files[0]
            self.assertNotIn("..", latest["stored_filename"])
            self.assertFalse(latest["stored_filename"].startswith("/"))
            self.assertFalse(latest["stored_filename"].startswith("\\"))

    # ------------------------------------------------------------------
    # 3. Secure File Download & IDOR Authorization Tests
    # ------------------------------------------------------------------
    def test_12_unauthorized_download_idor_defense(self):
        """
        Verify IDOR protection:
        Alice uploaded File 1. Bob registers, logs in, and attempts to download File 1.
        The application must deny access with HTTP 403 Forbidden.
        """
        # Ensure any previous session is cleared
        self.client.get("/logout")

        # Register Bob
        self.client.post("/register", data={
            "username": "bob",
            "email": "bob@college.edu",
            "password": "BobsPassword456!",
            "confirm_password": "BobsPassword456!"
        }, follow_redirects=True)

        # Log in as Bob
        self.client.post("/login", data={
            "username": "bob",
            "password": "BobsPassword456!"
        }, follow_redirects=True)

        # Attempt to access File ID 1 (which belongs to Alice)
        response = self.client.get("/download/1", follow_redirects=False)
        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------
    # 4. HTTP Security Headers Verification
    # ------------------------------------------------------------------
    def test_13_security_headers_present(self):
        """Verify that defensive HTTP response headers are sent."""
        response = self.client.get("/")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

if __name__ == "__main__":
    unittest.main(verbosity=2)
