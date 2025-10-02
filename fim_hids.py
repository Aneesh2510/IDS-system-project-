# fim_hids.py

import os
import json
import time
from config import CRITICAL_PATHS, BASELINE_FILE, CHECK_INTERVAL_SECONDS
from utils import calculate_sha256, log_event, log_alert

# Global dictionary for the baseline hashes
# NOTE: The 'global' keyword is NOT used here at the module level.
baseline_store = {}

def initialize_baseline():
    """Sets or loads the initial known-good hash baseline."""
    
    # FIX: The 'global' keyword is correctly placed here at the start of the function 
    # because this function modifies the global variable.
    global baseline_store 
    
    log_event("INFO", "--- Initializing HIDS Baseline ---")
    
    # Check if a baseline file already exists
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, 'r') as f:
                baseline_store = json.load(f) 
            log_event("INFO", f"Loaded existing baseline from {BASELINE_FILE}.")
            return
        except json.JSONDecodeError:
            log_event("ERROR", f"Failed to load baseline from {BASELINE_FILE}. Creating new baseline.")

    # Create a new baseline if one wasn't loaded
    new_baseline = {}
    for filepath in CRITICAL_PATHS:
        file_hash = calculate_sha256(filepath)
        if file_hash:
            new_baseline[filepath] = file_hash
            log_event("INFO", f"Baseline set for {os.path.basename(filepath)}.")
        else:
            log_event("WARNING", f"File not found or inaccessible: {filepath}. Skipping.")

    # Save the new baseline and update the global store
    try:
        with open(BASELINE_FILE, 'w') as f:
            json.dump(new_baseline, f, indent=4)
        
        baseline_store = new_baseline
        log_event("INFO", "New baseline successfully saved.")
    except Exception as e:
        log_event("ERROR", f"Failed to save new baseline: {e}")


def check_integrity():
    """Runs the periodic integrity check against the baseline."""
    log_event("INFO", "Running integrity check...")
    
    # We read from the global baseline_store dictionary (no 'global' keyword needed for reading)
    for filepath, baseline_hash in baseline_store.items():
        current_hash = calculate_sha256(filepath)
        
        # 1. Check for file removal/inaccessibility
        if current_hash is None:
            log_alert(filepath, baseline_hash, "FILE NOT FOUND/INACCESSIBLE")
            return True # Intrusion detected
            
        # 2. Check for content modification
        if current_hash != baseline_hash:
            log_alert(filepath, baseline_hash, current_hash)
            return True # Intrusion detected
        else:
            log_event("DEBUG", f"File {os.path.basename(filepath)} is OK.", print_to_console=False)
            
    return False # No intrusion detected


def start_monitoring():
    """The main entry point to start the HIDS."""
    initialize_baseline()
    
    if not baseline_store:
        log_event("ERROR", "No files were successfully baselined. Exiting monitor.")
        return

    log_event("INFO", f"HIDS Monitoring started. Interval: {CHECK_INTERVAL_SECONDS}s.")
    
    # Main monitoring loop
    while True:
        if check_integrity():
            break # Exit the loop immediately on critical alert
        
        # Pause until the next check
        time.sleep(CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    start_monitoring()