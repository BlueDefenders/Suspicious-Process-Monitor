Suspicious Process Monitor - README

Project Overview

The Suspicious Process Monitor is a real-time security tool designed for SOC analysts, cybersecurity professionals, and system administrators. It detects, logs, and terminates suspicious processes running on a machine by leveraging process name detection, SHA-256 hashing, and VirusTotal API integration to identify malicious behavior.

Features
✔ Real-time process monitoring – Scans active processes for suspicious behavior.
✔ Automatic threat termination – Instantly terminates flagged processes.
✔ SHA-256 Hash Calculation – Computes file hashes for deeper malware analysis.
✔ VirusTotal API integration – Cross-checks process hashes with a global threat intelligence database.
✔ Logging system – Stores detected threats in a CSV log for forensic analysis.
✔ Lightweight & efficient – Runs in the background with minimal system impact.

Installation
1. Prerequisites
Ensure Python 3.6+ is installed on your system. Install required dependencies:

pip install psutil pandas requests

2. Configure VirusTotal API (Optional but Recommended)

To enable VirusTotal API scanning, obtain an API key from VirusTotal and add it to the script:

VT_API_KEY = "your_virustotal_api_key"

How to Run the Program

1. Running the Script

Simply execute the script:

python suspicious_process_monitor.py

The tool will continuously monitor running processes and log any suspicious activity.

2. Output & Logs

If a suspicious process is found, it will be terminated automatically.

All flagged processes will be logged in suspicious_processes.log.

Example log entry:

Time,PID,Process Name,Command Line,File Path,SHA-256 Hash,VirusTotal Detection
2024-03-15 10:30:00,1234,cmd.exe,/c powershell,C:\Windows\System32\cmd.exe,3a4f...d78c,Detected by 5 AVs

How the Program Works

1. Process Name & Command-Line Scanning

The script checks each running process against a predefined list of malicious keywords (mimikatz, powershell, nc.exe, etc.).

If a match is found, the process is flagged for review.

2. SHA-256 Hashing & VirusTotal Lookup

The executable file of each suspicious process is hashed using SHA-256.

The hash is then sent to VirusTotal API to check if the process is known malware.

3. Automatic Process Termination

If a process is deemed malicious, it is terminated immediately to prevent further execution.

Customization Options

Modify Suspicious Keywords

To add more keywords, edit the SUSPICIOUS_KEYWORDS list in the script:

SUSPICIOUS_KEYWORDS = ["mimikatz", "nc.exe", "malware.exe", "backdoor"]

Disable Process Termination

If you only want to log threats without killing processes, comment out this line:

terminate_process(proc.info['pid'])

Change Log File Location

Modify the log file path in LOG_FILE:

LOG_FILE = "/var/logs/suspicious_processes.log"  # Linux path example

Use Cases

✔ SOC Threat Hunting – Detect malicious tools running on corporate endpoints.
✔ Incident Response – Kill ransomware or unauthorized access processes in real-time.
✔ System Monitoring – Track anomalies in production environments.
✔ Forensic Analysis – Store logs for post-attack investigations.

Legal Disclaimer
This tool is intended for ethical cybersecurity research, system monitoring, and SOC operations. Unauthorized use or deployment on systems you do not own may violate laws like the UK Computer Misuse Act, GDPR, and the CFAA. Use responsibly! 🚀
