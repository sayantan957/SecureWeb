import os
import re
import uuid
from pathlib import Path
import filetype
from werkzeug.utils import secure_filename
from config import Config
from logger import security_logger

# Magic byte signatures for authorized file formats
# These first bytes of a file define its true file format regardless of extension
MAGIC_NUMBERS = {
    "pdf": [b"%PDF-"],
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "jpeg": [b"\xff\xd8\xff"],
    "docx": [b"PK\x03\x04"]  # Microsoft Office OpenXML ZIP archive header
}

def sanitize_and_check_path(filename: str, base_folder: Path) -> Path:
    """
    Prevents Path Traversal vulnerabilities (e.g., ../../../app.py).
    Ensures that resolved path stays strictly within the intended base directory.
    """
    safe_name = secure_filename(filename)
    if not safe_name:
        safe_name = uuid.uuid4().hex

    resolved_path = (base_folder / safe_name).resolve()
    base_folder_resolved = base_folder.resolve()

    # Verify directory boundary
    try:
        resolved_path.relative_to(base_folder_resolved)
    except ValueError:
        security_logger.error(f"PATH TRAVERSAL ATTEMPT DETECTED: {filename}")
        raise ValueError("Invalid file path: path traversal detected.")

    return resolved_path

def validate_filename_and_extension(filename: str):
    """
    Validates the filename against dangerous patterns and checks extensions.
    Detects:
    - Missing or empty filenames
    - Prohibited dangerous extensions (.exe, .php, .js, .bat, etc.)
    - Multi-extension bypass attempts (.php.jpg, .pdf.exe, .jpg;.php)
    - Enforces allowed extension whitelist (.pdf, .jpg, .jpeg, .png, .docx)
    
    Returns:
        tuple (is_valid: bool, error_message: str, extension: str)
    """
    if not filename or filename.strip() == "":
        return False, "No file was selected.", ""

    # Check for path traversal characters in raw original filename
    if ".." in filename or "/" in filename or "\\" in filename:
        security_logger.warning(f"Suspect filename with path traversal characters: {filename}")
        # Note: we still clean it up, but log the event

    # Normalize name to lowercase for validation checks
    clean_name = filename.lower().strip()

    # Split by dot to inspect all extension components
    parts = clean_name.split(".")
    if len(parts) < 2:
        return False, "File must have a valid extension.", ""

    # Check for dangerous extensions anywhere in the parts list
    # e.g., 'payload.php.jpg' or 'exploit.exe.png'
    for part in parts[1:]:
        if part in Config.DANGEROUS_EXTENSIONS:
            security_logger.warning(
                f"REJECTED: Dangerous extension component '{part}' in filename: {filename}"
            )
            return False, f"Dangerous file type detected (.{part} is strictly forbidden).", ""

    # The actual extension is the last segment
    final_ext = parts[-1]

    # Verify against allowed whitelist
    if final_ext not in Config.ALLOWED_EXTENSIONS:
        security_logger.warning(
            f"REJECTED: Unauthorized extension '.{final_ext}' for file: {filename}"
        )
        return False, (
            f"Extension '.{final_ext}' is not permitted. "
            f"Allowed types: {', '.join(sorted(Config.ALLOWED_EXTENSIONS))}"
        ), ""

    return True, "", final_ext

def validate_magic_bytes_and_mime(file_stream, declared_ext: str):
    """
    Inspects the actual binary headers (magic bytes) to defeat MIME-type spoofing.
    Even if an attacker renames 'shell.php' to 'shell.png', this function will
    read the raw bytes and detect that it is NOT a valid PNG file.
    
    Returns:
        tuple (is_valid: bool, error_message: str, detected_mime: str)
    """
    # Read the first 2048 bytes for signature inspection
    sample_bytes = file_stream.read(2048)
    file_stream.seek(0)  # Rewind the file pointer so subsequent reads succeed

    if len(sample_bytes) == 0:
        return False, "Uploaded file is empty (0 bytes).", ""

    # Step 1: Check raw signature prefix against our expected magic numbers
    expected_headers = MAGIC_NUMBERS.get(declared_ext, [])
    has_valid_magic_header = False
    for header in expected_headers:
        if sample_bytes.startswith(header):
            has_valid_magic_header = True
            break

    # Step 2: Use filetype library for deeper MIME detection
    kind = filetype.guess(sample_bytes)
    detected_mime = kind.mime if kind else "unknown/octet-stream"

    # For DOCX files: DOCX is an OpenOffice XML zip package.
    # filetype might detect application/zip, which is valid for .docx
    if declared_ext == "docx":
        if has_valid_magic_header or (kind and kind.extension in ["zip", "docx"]):
            return True, "", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    # For PDF files:
    if declared_ext == "pdf":
        if has_valid_magic_header or (kind and kind.extension == "pdf"):
            return True, "", "application/pdf"

    # For Images:
    if declared_ext in ["jpg", "jpeg"]:
        if has_valid_magic_header and (kind and kind.extension in ["jpg", "jpeg"]):
            return True, "", "image/jpeg"

    if declared_ext == "png":
        if has_valid_magic_header and (kind and kind.extension == "png"):
            return True, "", "image/png"

    # If magic bytes mismatch the declared extension: MIME-Type Spoofing Detected!
    security_logger.warning(
        f"MIME SPOOFING ATTEMPT: Declared extension '.{declared_ext}' "
        f"does not match detected header/MIME: {detected_mime}"
    )
    return False, (
        f"File content verification failed. The file claims to be '.{declared_ext}', "
        f"but its binary signature does not match (detected: {detected_mime})."
    ), detected_mime

def generate_secure_storage_name(declared_ext: str) -> str:
    """
    Generates a cryptographically random UUIDv4 storage filename.
    Guarantees:
    - User input never controls the disk filename
    - Prevents file collisions and overwriting
    - Prevents direct file guessing or enumeration
    """
    return f"{uuid.uuid4().hex}.{declared_ext}"
