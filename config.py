# config.py

import os

# --- HIDS Configuration ---

# Files/directories to monitor (REQUIRED: Change these to paths on your system)

CRITICAL_PATHS = [
    # config.py - CORRECTED STRUCTURE

# Files/directories to monitor (REQUIRED: Change these to real paths on your system!)
    # 1. Path to your first test file
    r"C:\Users\anees\OneDrive\Desktop\IDS Project\test_file_1.txt", 
    
    # 2. Path to your second test file
    r"C:\Users\anees\OneDrive\Desktop\IDS Project\test_file_2.txt", 
    
    # 3. Add more files if needed
    # r"C:\Users\anees\Desktop\another_file.ini", 
]

# ... rest of config.py ...

# Monitoring interval in seconds
CHECK_INTERVAL_SECONDS = 5

# --- Persistence and Logging Files ---

# File to store the known-good baseline hashes (JSON format)
BASELINE_FILE = "baseline_hashes.json"

# File to log all security events (normal checks, warnings, and alerts)
LOG_FILE = "security_events.log"