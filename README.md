# Secure File Upload & Malware Detection System Using Flask

A comprehensive, defense-in-depth college cybersecurity project developed with **Python**, **Flask**, **SQLite**, and **ClamAV**.

---

## 📌 Project Overview

Unrestricted file upload is one of the most severe web vulnerabilities (OWASP Top 10), frequently leading to Remote Code Execution (RCE), defacement, malware distribution, and complete server compromise. 

This project implements a multi-layered security pipeline that validates incoming files across multiple criteria, scans them for malicious code with ClamAV, stores them outside the web root under randomized identifiers, enforces strict authorization for downloads, and maintains a security audit trail.

---

## 🛡️ Security Architecture & Defense-in-Depth Pipeline

```
[ User Browser ]
       │
       ▼
1. HTTP Security Headers (X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy)
       │
       ▼
2. Session Authentication Guard (@login_required)
       │
       ▼
3. Multi-Layer File Validation
   ├── Size Limit Check (10 MB via MAX_CONTENT_LENGTH)
   ├── Extension Whitelisting (.pdf, .jpg, .jpeg, .png, .docx)
   ├── Double Extension & Dangerous Component Inspection (blocks .php.jpg, etc.)
   └── Magic Byte Header Inspection (verifies actual binary file signature)
       │
       ▼
4. Quarantine Staging (temp_uploads/ with random UUIDv4)
       │
       ▼
5. ClamAV Antivirus Scanning (clamscan / clamd TCP)
   ├── If Malicious: Permanently wiped from disk, alert logged, user notified
   └── If Clean: Moved to permanent vault (uploads/ outside static/)
       │
       ▼
6. Protected Database Record (SQLite database.db)
       │
       ▼
7. Secure File Serving (Owner verification check; served via send_from_directory)
```

---

## 🚀 Quick Start Guide (Windows)

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.14 on Windows)
- PowerShell or Command Prompt

### 2. Virtual Environment Setup
Open PowerShell in the project directory:

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1
# (Or in CMD: .venv\Scripts\activate.bat)

# Install required dependencies
pip install -r requirements.txt
```

### 3. Environment Variables
A default `.env` file is included. You can customize settings:
```ini
SECRET_KEY=your_secure_hex_key_here
MAX_CONTENT_LENGTH_MB=10
CLAMSCAN_PATH=C:\Program Files\ClamAV\clamscan.exe
CLAMD_HOST=127.0.0.1
CLAMD_PORT=3310
```

### 4. Run the Application
```powershell
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🦠 ClamAV Setup on Windows

ClamAV is a free and open-source antivirus engine. The application integrates with ClamAV via CLI (`clamscan.exe`) or background daemon (`clamd`).

> [!NOTE]
> If ClamAV is not yet installed on your system, the application gracefully flags files with status **Scanner Offline (`scanner_unavailable`)** instead of falsely claiming they are clean.

### Windows Installation Steps:
1. **Download ClamAV for Windows**:
   - Visit the official portal: [https://www.clamav.net/downloads](https://www.clamav.net/downloads)
   - Download the official 64-bit Windows installer (`.msi` or `.zip`).
   - Run the installer. By default, it installs to: `C:\Program Files\ClamAV`.

2. **Initialize Configuration Files**:
   - In `C:\Program Files\ClamAV`, copy `freshclam.conf.sample` to `freshclam.conf`.
   - Copy `clamd.conf.sample` to `clamd.conf`.
   - Open both files in Notepad and comment out or delete the word `Example` near line 8.

3. **Download Antivirus Definitions**:
   Open PowerShell as Administrator and run:
   ```powershell
   cd "C:\Program Files\ClamAV"
   .\freshclam.exe
   ```
   This downloads the latest signature databases (`main.cvd`, `daily.cvd`, `bytecode.cvd`).

4. **Verify ClamAV Works**:
   ```powershell
   .\clamscan.exe --version
   ```

5. **Connect to Flask**:
   - Ensure the path in `.env` matches your installation:
     `CLAMSCAN_PATH=C:\Program Files\ClamAV\clamscan.exe`
   - Restart Flask (`python app.py`). Uploads will now be scanned against live virus definitions!

---

## 🧪 Automated Security Tests

A complete automated unit testing suite verifies all 10 security threats:

```powershell
.\.venv\Scripts\python -m unittest test_security.py -v
```

### Test Suite Output:
- `test_01`: User Registration & Cryptographic Password Hashing (scrypt/pbkdf2)
- `test_02`: Authentication, Session Security & Enumeration Defense
- `test_03`: Valid PDF Upload (Magic Byte `%PDF-`)
- `test_04`: Valid JPG Upload (Magic Byte `\xff\xd8\xff`)
- `test_05`: Executable (.exe) Upload Rejection
- `test_06`: Server-Side Script (.php) Rejection
- `test_07`: Client-Side Script (.js) Rejection
- `test_08`: Double Extension Attack (`shell.php.jpg`) Blocked
- `test_09`: MIME-Type Spoofing Detection (PHP disguised as .jpg)
- `test_10`: Malware Detection using harmless EICAR test string
- `test_11`: Path Traversal Filename Prevention (`../../../evil.pdf`)
- `test_12`: Insecure Direct Object Reference (IDOR) Download Defense (HTTP 403)
- `test_13`: HTTP Security Headers Verification (CSP, X-Frame-Options, etc.)

---

## 🔬 Safe Lab Testing Instructions

### 1. Testing Legitimate Files
- Register an account (e.g. `testuser` / `TestPassword123!`).
- Navigate to **Upload File**.
- Upload a standard `.pdf`, `.png`, or `.jpg`.
- Observe the file appear in your Dashboard with its metadata and a download button.

### 2. Testing Threat Rejections
- **Dangerous Extension**: Rename a text file to `exploit.php` or `virus.exe`. Upload it. You will see a flash alert: *"Dangerous file type detected"*.
- **Double Extension**: Rename a file to `invoice.php.pdf`. Upload it. The system detects `.php` in the filename segments and blocks it.
- **MIME Spoofing**: Create a text file containing `<?php echo "evil"; ?>` and name it `fake.jpg`. Upload it. The magic byte analyzer catches that the first bytes are NOT `\xff\xd8\xff` and rejects the upload.
- **EICAR Malware Test**: The EICAR test file is an industry-standard, harmless 68-character string designed specifically to test antivirus scanners safely.
  ```
  X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
  ```
  Save this inside a file named `eicar.pdf` starting with `%PDF-1.4\n`. Upload it. The system triggers a **Malware Alert**, rejects the upload, and wipes it immediately from the staging folder.
- **IDOR Protection**: Log out, register a second account (e.g. `attacker`), and try manually navigating to `http://127.0.0.1:5000/download/1`. The application verifies user ownership and denies access with an **HTTP 403 Forbidden** response.

---

## 📁 Project Structure

```
project/
│
├── app.py                  # Main Flask application and secure route handlers
├── config.py               # Security parameters, thresholds, and path configurations
├── database.py             # SQLite database schemas and query helper functions
├── validators.py           # Multi-layer file validation and magic-byte inspections
├── scanner.py              # ClamAV antivirus scanning engine with offline fallback
├── logger.py               # Rotating security audit logger (logs/security.log)
├── test_security.py        # Automated security test suite (13 test cases)
├── requirements.txt        # Python dependency manifest
├── .env.example            # Template for environment configuration
├── .env                    # Active environment settings
├── .gitignore              # Git ignore rules for virtualenvs, databases, logs
├── database.db             # Local SQLite database (auto-generated)
├── README.md               # Complete project documentation and guide
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Core layout shell with navigation and alerts
│   ├── index.html          # Public landing and overview page
│   ├── login.html          # Secure login form
│   ├── register.html       # Secure registration form
│   ├── dashboard.html      # Protected user file vault dashboard
│   └── upload.html         # Protected file ingestion and scan interface
│
├── static/
│   └── css/
│       └── style.css       # Clean, modern cybersecurity-themed stylesheet
│
├── uploads/                # Secure permanent storage vault (outside static/)
├── temp_uploads/           # Quarantine staging directory for unscanned files
└── logs/
    └── security.log        # Real-time security audit log
```

---

## 📜 License
Open-source under the MIT License. Developed for educational and cybersecurity lab demonstrations.
