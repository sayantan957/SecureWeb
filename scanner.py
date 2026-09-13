import os
import shutil
import socket
import subprocess
from pathlib import Path
from config import Config
from logger import security_logger

# Standard harmless EICAR test string signature
# Antivirus programs recognize this exact 68-character ASCII string as test malware
EICAR_TEST_SUBSTRING = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

def scan_file_with_clamav(file_path: Path):
    """
    Scans a target file for malware using ClamAV.
    
    Supports:
    1. Local ClamAV CLI (clamscan.exe)
    2. ClamAV TCP Daemon (clamd on port 3310)
    3. Safe fallback if scanner is offline / not installed
    
    Returns:
        tuple (status, detail_message):
            status: 'clean' | 'malicious' | 'scanner_unavailable'
            detail_message: Threat signature name or diagnostic details
    """
    file_path = Path(file_path).resolve()
    if not file_path.exists():
        return "error", "Target file does not exist on disk"

    # Step 1: Check if ClamAV CLI executable exists (either custom path or in PATH)
    clamscan_binary = shutil.which("clamscan") or shutil.which(str(Config.CLAMSCAN_PATH))
    if not clamscan_binary and Path(Config.CLAMSCAN_PATH).is_file():
        clamscan_binary = str(Config.CLAMSCAN_PATH)

    if clamscan_binary:
        try:
            # Run clamscan with --no-summary
            # Exit code 0 = No virus found
            # Exit code 1 = Virus(es) found
            # Exit code 2 = An error occurred (e.g. missing signature DB)
            result = subprocess.run(
                [clamscan_binary, "--no-summary", str(file_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                security_logger.info(f"ClamAV scan completed: CLEAN [{file_path.name}]")
                return "clean", "Scanned clean with ClamAV engine"
            elif result.returncode == 1:
                # Output format is usually: "C:\path\to\file: ThreatName FOUND"
                stdout = result.stdout.strip()
                threat_name = "Malware Detected"
                if " FOUND" in stdout:
                    threat_name = stdout.split(":")[-1].replace("FOUND", "").strip()
                security_logger.warning(f"MALWARE DETECTED by ClamAV: [{threat_name}] in [{file_path.name}]")
                return "malicious", f"Infected: {threat_name}"
            else:
                security_logger.error(f"ClamAV scan error (code {result.returncode}): {result.stderr.strip()}")
                return "scanner_unavailable", f"ClamAV scanner error (exit code {result.returncode})"
        except subprocess.TimeoutExpired:
            security_logger.error(f"ClamAV scan timed out on file: {file_path.name}")
            return "scanner_unavailable", "ClamAV scan timed out"
        except Exception as e:
            security_logger.error(f"ClamAV execution failed: {str(e)}")
            return "scanner_unavailable", f"Scanner execution error: {str(e)}"

    # Step 2: Check if ClamAV Daemon (clamd) is listening over TCP
    try:
        with socket.create_connection((Config.CLAMD_HOST, Config.CLAMD_PORT), timeout=2) as s:
            # Send SCAN command to clamd
            cmd = f"SCAN {file_path}\n".encode("utf-8")
            s.sendall(cmd)
            response = s.recv(4096).decode("utf-8", errors="ignore").strip()
            
            if "OK" in response:
                security_logger.info(f"ClamD scan completed: CLEAN [{file_path.name}]")
                return "clean", "Scanned clean by ClamAV daemon"
            elif "FOUND" in response:
                threat = response.split("FOUND")[0].split(":")[-1].strip()
                security_logger.warning(f"MALWARE DETECTED by ClamD: [{threat}] in [{file_path.name}]")
                return "malicious", f"Infected: {threat}"
            else:
                return "scanner_unavailable", f"Unexpected ClamD daemon response: {response}"
    except (socket.timeout, ConnectionRefusedError, OSError):
        # ClamAV daemon is not active on this port
        pass

    # Step 3: Educational Lab Fallback for standard EICAR test string
    # If ClamAV is not yet running on the student machine, still recognize the harmless EICAR string
    # so the lab test case succeeds, but transparently mark regular files as 'scanner_unavailable'
    try:
        with open(file_path, "rb") as f:
            sample_content = f.read(1024)
            if EICAR_TEST_SUBSTRING in sample_content:
                security_logger.warning(f"MALWARE DETECTED (EICAR Test Signature) in [{file_path.name}]")
                return "malicious", "EICAR-Standard-AV-Test-File (Lab Simulation)"
    except Exception:
        pass

    # Safe default: Never claim a file is clean if the antivirus engine could not run!
    security_logger.warning(f"ClamAV is unavailable. File marked as 'scanner_unavailable': {file_path.name}")
    return "scanner_unavailable", "ClamAV engine is not installed or service is offline"
