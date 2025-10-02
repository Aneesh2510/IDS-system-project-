# utils.py

import hashlib
import time
from config import LOG_FILE

def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file."""
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as file:
            # Read in chunks to handle large files efficiently
            while True:
                chunk = file.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except IOError:
        # File doesn't exist or permission denied
        return None

def log_event(level, message, print_to_console=True):
    """Writes a timestamped message to the log file and optionally prints it."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] [{level}] {message}"
    
    with open(LOG_FILE, 'a') as f:
        f.write(log_message + "\n")
        
    if print_to_console:
        print(log_message)

def log_alert(filepath, baseline, current):
    """Logs a critical intrusion alert."""
    alert_msg = (
        "\n" + "="*80 + "\n"
        "!!! CRITICAL INTRUSION ALERT: FILE TAMPERING DETECTED !!!\n"
        f"FILE: {filepath}\n"
        f"BASELINE HASH: {baseline}\n"
        f"CURRENT HASH:  {current}\n"
        "ACTION: System integrity compromised. Monitoring stopped.\n"
        "="*80 + "\n"
    )
    log_event("ALERT", alert_msg, print_to_console=True)