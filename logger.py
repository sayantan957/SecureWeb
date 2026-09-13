import logging
from logging.handlers import RotatingFileHandler
from config import Config

def setup_security_logger():
    """
    Configure a dedicated rotating security audit logger.
    Logs to logs/security.log with timestamps, severity, and event details.
    Does NOT log sensitive information such as plaintext passwords.
    """
    Config.LOGS_FOLDER.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger("security_audit")
    logger.setLevel(logging.INFO)
    
    # Avoid adding duplicate handlers if re-initialized
    if not logger.handlers:
        # Rotating log file: max 5 MB per file, keep 3 backup rotations
        handler = RotatingFileHandler(
            Config.SECURITY_LOG_PATH,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [SECURITY] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # Also log to console for development visibility
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
    return logger

# Singleton security logger instance
security_logger = setup_security_logger()
