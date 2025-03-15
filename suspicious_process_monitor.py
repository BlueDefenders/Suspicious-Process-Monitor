import psutil
import pandas as pd
import datetime
import os
import hashlib
import requests

# Define suspicious process names and keywords
SUSPICIOUS_KEYWORDS = ["mimikatz", "nc.exe", "powershell", "meterpreter", "cmd.exe", "nmap"]

# VirusTotal API Key (Replace with your API Key)
VT_API_KEY = "your_virustotal_api_key"
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Log file to store detected suspicious activities
LOG_FILE = "suspicious_processes.log"

def get_file_hash(filepath):
    """Computes SHA-256 hash of a file."""
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def check_virustotal(file_hash):
    """Checks a file hash against VirusTotal's database."""
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_URL}{file_hash}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        detections = data["data"]["attributes"]["last_analysis_stats"]
        return detections
    return None

def detect_suspicious_processes():
    """Scans running processes for suspicious behavior."""
    suspicious_processes = []

    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
        try:
            process_name = proc.info['name'].lower()
    """Main function to run the process monitor."""
    print("🔍 Monitoring processes for suspicious activity...")
    while True:
        suspicious_processes = detect_suspicious_processes()
        if suspicious_processes:
            log_suspicious_activity(suspicious_processes)

if __name__ == "__main__":
    main()
