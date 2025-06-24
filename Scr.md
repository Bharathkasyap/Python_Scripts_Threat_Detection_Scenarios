🛡️ Python Script Library for Proactive Cyber Threat Hunting and Remediation
📖 Introduction
In today's evolving threat landscape, proactive threat hunting is indispensable for identifying and neutralizing sophisticated malicious activities that bypass traditional security defenses. This practice involves meticulously sifting through system and network logs, parsing vast amounts of event data, and identifying subtle behavioral anomalies indicative of compromise.

Python scripting empowers cybersecurity analysts and threat hunters to significantly enhance their capabilities by automating repetitive analysis tasks, rapidly parsing diverse log formats, enriching threat indicators, and even simulating attack or response scenarios. When combined with powerful Bash terminal execution, these scripts can be seamlessly deployed across endpoints or centrally managed for comprehensive investigative and remedial actions.

This repository features a curated collection of 30 Python scripts, meticulously categorized by common threat detection and response use cases. These scripts are designed to equip security professionals with practical tools to:

Parse and analyze critical security logs: Including Sysmon, DNS, Windows Event Logs, and Email logs.

Detect early indicators of compromise (IOCs): Identifying suspicious patterns before they escalate.

Monitor for advanced attack techniques: Such as lateral movement, data exfiltration, and persistence mechanisms.

Automate the investigation and initial response to suspicious activities.

🚀 Script Catalog
Below is a detailed catalog of the scripts included in this library, outlining their primary objective, ideal use cases, and execution instructions. Each script is designed for practical application in real-world threat hunting scenarios.

Goal
Identify suspicious parent-child process relationships (e.g., winword.exe spawning cmd.exe).

Use Case
Post-phishing email analysis, investigation of macro-enabled document execution.

Python Code
import pandas as pd

df = pd.read_csv('../data_samples/sysmon_logs.csv')
df["ParentImage"] = df["ParentImage"].str.lower()
df["Image"] = df["Image"].str.lower()

suspicious_parents = ["winword.exe", "excel.exe", "outlook.exe"]
suspicious_children = ["cmd.exe", "powershell.exe", "wscript.exe"]

matches = df[
    df["ParentImage"].isin(suspicious_parents) &
    df["Image"].isin(suspicious_children)
]

if not matches.empty:
    print("⚠️ Suspicious parent-child process behavior found:")
    print(matches[["UtcTime", "ParentImage", "Image", "CommandLine"]])
else:
    print("✅ No anomalies detected.")

Execution
python scripts/1_detect_suspicious_processes.py

Goal
Automate the uninstallation of outdated or vulnerable software via Windows Remote Management (WinRM).

Use Case
Post-vulnerability assessment remediation, rapid patch deployment.

Python Code
import winrm

# Establish a WinRM session to the target host
session = winrm.Session('http://target-ip:5985/wsman', auth=('admin', 'password'))

# Query for installed Adobe products
command = r'wmic product where "Name like \'%Adobe%\'" get Name, Version'
result = session.run_cmd(command)
output = result.std_out.decode()

if "Adobe Reader XI" in output:
    # Trigger silent uninstallation for Adobe Reader XI
    uninstall_cmd = r'msiexec /x {AC76BA86-7AD7-1033-7B44-AB0000000001} /quiet'
    session.run_cmd(uninstall_cmd)
    print("✅ Uninstallation triggered for Adobe Reader XI.")
else:
    print("✅ No outdated Adobe Reader XI found.")

Execution
python scripts/2_vulnerable_software_removal.py

Goal
Leverage the VirusTotal API to check the reputation of file hashes.

Use Case
Malware triage, initial assessment of suspicious file indicators.

Python Code
import requests

# Replace with your actual VirusTotal API Key
API_KEY = 'YOUR_VT_API_KEY'
hashes = ['44d88612fea8a8f36de82e1278abb02f', 'example_hash_2', 'example_hash_3'] # Add more hashes as needed

print("--- VirusTotal Hash Check ---")
for h in hashes:
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": API_KEY}
    
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        data = resp.json()
        
        # Check if 'data' and 'attributes' keys exist to prevent errors
        if 'data' in data and 'attributes' in data['data'] and 'last_analysis_stats' in data['data']['attributes']:
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            print(f"Hash: {h} | Malicious Detections: {positives}")
        else:
            print(f"Hash: {h} | No analysis data found or invalid hash.")

    except requests.exceptions.RequestException as e:
        print(f"Error checking hash {h}: {e}")
    except KeyError:
        print(f"Hash: {h} | Data not found or API key may be invalid.")
print("--- Check Complete ---")

Execution
python scripts/3_virus_total_hash_checker.py

Goal
Detect potential brute-force login attempts by identifying an excessive number of failed login events from a single source IP.

Use Case
Investigation of account lockouts, analysis of anomalous login patterns.

Python Code
import pandas as pd

df = pd.read_csv('../data_samples/login_data.csv')
# Filter for failed login attempts and group by source IP
grouped = df[df["status"] == "failed"].groupby("source_ip").size().reset_index(name='failed_attempts')

# Identify suspicious IPs with more than 10 failed attempts
suspicious = grouped[grouped["failed_attempts"] > 10]

if not suspicious.empty:
    print("⚠️ Suspicious IPs with high failed login attempts:")
    print(suspicious)
else:
    print("✅ No suspicious brute-force attempts detected based on failed logins.")

Execution
python scripts/4_failed_login_brute_force.py

Goal
Identify large file transfers to USB devices, often indicative of data exfiltration.

Use Case
Investigation of suspected insider threats, data loss prevention (DLP) monitoring.

Python Code
import pandas as pd

df = pd.read_csv('../data_samples/event_logs_sample.csv')

# Filter for specific event ID related to object access (e.g., 4663 for file system access)
usb_events = df[df["EventID"] == 4663]

# Further filter for write operations to typical USB drive paths (e.g., removable drives like 'E:\')
usb_writes = usb_events[usb_events["ObjectName"].str.contains("E:\\", na=False)]

# Identify large transfers (e.g., > 10 MB)
large_transfers = usb_writes[usb_writes["ObjectSize"] > 10 * 1024 * 1024] # 10 MB in bytes

if not large_transfers.empty:
    print("⚠️ Detected large file transfers to USB devices:")
    print(large_transfers[["UtcTime", "SubjectUserName", "ObjectName", "ObjectSize"]])
else:
    print("✅ No large USB file transfers detected.")

Execution
python scripts/5_usb_exfiltration_detector.py

Goal
Retrieve detailed Common Vulnerabilities and Exposures (CVE) information from the National Vulnerability Database (NVD) API.

Use Case
During patch management research, vulnerability assessment, threat intelligence enrichment.

Python Code
import requests

cve_id = "CVE-2023-23397" # Example CVE ID
url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"

try:
    resp = requests.get(url)
    resp.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
    data = resp.json()

    # Navigate through the JSON structure to extract relevant information
    cve_item = data.get("result", {}).get("CVE_Items", [])[0]
    
    if cve_item:
        desc = cve_item["cve"]["description"]["description_data"][0]["value"]
        
        # Safely access severity, checking for nested keys
        severity = "N/A"
        impact_v3 = cve_item.get("impact", {}).get("baseMetricV3", {})
        if impact_v3:
            severity = impact_v3.get("cvssV3", {}).get("baseSeverity", "N/A")

        print(f"--- CVE Information for {cve_id} ---")
        print(f"Severity: {severity}")
        print(f"Description: {desc}")
        print("---------------------------------")
    else:
        print(f"No detailed information found for CVE: {cve_id}. It might not exist or data structure changed.")

except requests.exceptions.RequestException as e:
    print(f"Error fetching CVE information for {cve_id}: {e}")
except IndexError:
    print(f"No CVE data found for {cve_id}. Check if the CVE ID is correct.")
except KeyError as e:
    print(f"Missing expected key in JSON response for {cve_id}: {e}")

Execution
python scripts/6_cve_auto_lookup.py

Goal
Detect potential DNS tunneling by identifying unusually long or suspicious TXT record queries.

Use Case
Detection of C2 beaconing, data exfiltration via DNS.

Python Code
import pandas as pd

df = pd.read_csv('../data_samples/dns_logs.csv')

# Filter for TXT query types and query names longer than 100 characters (common in DNS tunneling)
suspicious = df[(df["query_type"] == "TXT") & (df["query_name"].str.len() > 100)]

if not suspicious.empty:
    print("⚠️ Suspicious DNS tunneling candidates detected:")
    print(suspicious[["timestamp", "client_ip", "query_name", "query_type"]])
else:
    print("✅ No suspicious DNS tunneling candidates detected.")

Execution
python scripts/7_dns_tunneling_detector.py

Goal
Perform a basic network port scan to identify open ports on a target host.

Use Case
Validating host exposure, identifying unauthorized services, network reconnaissance.

Python Code
import socket

target = '192.168.1.100' # Target IP address
ports = [21, 22, 23, 80, 443, 3389, 8080] # Common ports to scan

print(f"--- Scanning ports on {target} ---")
for port in ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Shorter timeout for faster scanning
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is OPEN")
        sock.close()
    except socket.error as e:
        print(f"Could not connect to port {port}: {e}")
print("--- Scan Complete ---")

Execution
python scripts/8_network_port_scanner.py

Goal
Check for the presence of specific Windows Knowledge Base (KB) updates on a system.

Use Case
Auditing patch compliance, identifying missing critical security updates.

Python Code
import subprocess

required_kbs = ["KB5027215", "KB5034441", "KBXXXXXXX"] # Add all required KBs
print("--- Checking Windows Patch Compliance ---")
try:
    output = subprocess.getoutput("wmic qfe get HotFixID")

    for kb in required_kbs:
        if kb in output:
            print(f"✅ {kb} is installed.")
        else:
            print(f"❌ {kb} is MISSING!")
except FileNotFoundError:
    print("Error: 'wmic' command not found. This script is intended for Windows systems.")
except Exception as e:
    print(f"An error occurred: {e}")
print("--- Compliance Check Complete ---")

Execution
python scripts/9_patch_compliance_checker.py

Goal
Monitor and detect successful Remote Desktop Protocol (RDP) sessions.

Use Case
Post-brute-force attack investigation, detection of off-hour or unauthorized RDP access.

Python Code
import pandas as pd

df = pd.read_csv('../data_samples/login_data.csv')

# Filter for successful RDP logon type (Type 10)
rdp_sessions = df[(df["LogonType"] == "10") & (df["Status"] == "success")]

if not rdp_sessions.empty:
    print("⚠️ Detected successful RDP sessions:")
    print(rdp_sessions[["timestamp", "source_ip", "user"]])
else:
    print("✅ No successful RDP sessions detected based on provided logs.")

Execution
python scripts/10_rdp_session_monitor.py

Goal
Detect obfuscated or suspicious PowerShell command execution.

Use Case
Investigation of phishing attacks, post-exploitation activities, macro-enabled malware.

Python Code
# Placeholder for actual detection logic.
# This script would typically parse PowerShell logs (e.g., Sysmon Event ID 4104)
# and look for indicators like encoded commands, unusual character sets, or long command lines.
print('Script executed. (Detection logic to be implemented based on specific log parsing needs)')

Execution
python scripts/11_suspicious_powershell_usage.py

Goal
Flag DNS queries or network connections to known malicious domains.

Use Case
After an IOC alert, investigation of phishing email links, network traffic analysis.

Python Code
# Placeholder for actual detection logic.
# This script would typically ingest DNS or network connection logs
# and compare queried domains against a blacklist of known malicious domains.
print('Script executed. (Detection logic to be implemented based on specific log parsing and threat intelligence feeds)')

Execution
python scripts/12_malicious_domain_checker.py

Goal
Extract and analyze browser activity (history, downloads, cookies).

Use Case
Forensic analysis for phishing investigations, malicious link clicks, or data exfiltration via web.

Python Code
# Placeholder for actual extraction and analysis logic.
# This script would require libraries like 'browser_history' or direct SQLite parsing
# of browser database files (e.g., Chrome, Firefox).
print('Script executed. (Browser history extraction and analysis logic to be implemented)')

Execution
python scripts/13_browser_history_analyzer.py

Goal
Detect common process injection techniques.

Use Case
When LSASS memory tampering, privilege escalation, or advanced malware activity is suspected.

Python Code
# Placeholder for actual detection logic.
# This script would typically analyze Sysmon Event ID 8 (CreateRemoteThread) or Event ID 10 (ProcessAccess)
# for unusual access patterns or remote thread creation in legitimate processes.
print('Script executed. (Process injection detection logic to be implemented)')

Execution
python scripts/14_process_injection_detector.py

Goal
Detect indicators of Mimikatz usage based on Sysmon logs.

Use Case
Credential dumping detection, lateral movement investigation.

Python Code
# Placeholder for actual detection logic.
# This script would specifically look for Sysmon events related to LSASS access (Event ID 10)
# with specific access mask values, or suspicious process creations related to Mimikatz tools.
print('Script executed. (Mimikatz detection logic based on Sysmon to be implemented)')

Execution
python scripts/15_mimikatz_detection_sysmon.py

Goal
Identify user logins occurring outside of typical working hours.

Use Case
Detection of compromised accounts, insider threats, or unauthorized access.

Python Code
# Placeholder for actual detection logic.
# This script would analyze login logs (e.g., Windows Security Event ID 4624)
# and compare login times against defined normal operating hours.
print('Script executed. (Anomalous login time detection logic to be implemented)')

Execution
python scripts/16_anomalous_login_time.py

Goal
Detect simultaneous or rapidly sequential logins from geographically distant locations.

Use Case
Geo-location anomaly detection, compromised account identification.

Python Code
# Placeholder for actual detection logic.
# This script would require a GeoIP database (e.g., MaxMind) and would compare
# the geographical locations of consecutive login attempts for a user.
print('Script executed. (GeoIP login mismatch detection logic to be implemented)')

Execution
python scripts/17_geoip_login_mismatch.py

Goal
Find newly created or modified suspicious scheduled tasks.

Use Case
Persistence hunting, detection of lateral movement.

Python Code
# Placeholder for actual detection logic.
# This script would parse Windows Event Logs (e.g., Event ID 4698 for scheduled task creation)
# and look for unusual task names, actions, or associated executables.
print('Script executed. (Scheduled task abuse detection logic to be implemented)')

Execution
python scripts/18_scheduled_task_abuse.py

Goal
Find suspicious modifications to critical registry keys often used for persistence or privilege escalation.

Use Case
Persistence hunting, privilege escalation detection.

Python Code
# Placeholder for actual detection logic.
# This script would analyze Sysmon Event ID 12/13/14 (Registry Events)
# for modifications to common persistence locations (e.g., Run keys, BHOs, Image File Execution Options).
print('Script executed. (Suspicious registry modification detection logic to be implemented)')

Execution
python scripts/19_suspicious_registry_mods.py

Goal
Detect the creation of new and potentially malicious Windows services.

Use Case
Lateral movement detection, persistence establishment.

Python Code
# Placeholder for actual detection logic.
# This script would parse Windows Event Logs (e.g., Event ID 7045 for service creation)
# and look for services with suspicious names, paths, or associated user accounts.
print('Script executed. (Malicious service creation detection logic to be implemented)')

Execution
python scripts/20_service_creation_hunt.py

Goal
Parse and extract indicators (e.g., sender, subject, URLs, attachments) from reported phishing emails.

Use Case
Incident response for user-reported phishing, threat intelligence gathering.

Python Code
# Placeholder for actual parsing logic.
# This script would likely use email parsing libraries (e.g., `email` module)
# to extract headers, body content, and identify suspicious elements.
print('Script executed. (Phishing email indicator parsing logic to be implemented)')

Execution
python scripts/21_phishing_email_indicator_parser.py

Goal
Detect regular, periodic network connections to specific domains, indicative of command-and-control (C2) beaconing.

Use Case
C2 detection, identifying active malware communication.

Python Code
# Placeholder for actual detection logic.
# This script would analyze network flow data or DNS logs to identify
# repetitive, time-based communication patterns to external domains.
print('Script executed. (Beaconing domain hunt logic to be implemented)')

Execution
python scripts/22_beaconing_domain_hunt.py

Goal
Identify processes exhibiting non-standard execution paths or behaviors.

Use Case
Detection of masquerading, DLL hijacking, or other evasion techniques.

Python Code
# Placeholder for actual detection logic.
# This script would analyze process creation events (e.g., Sysmon Event ID 1)
# and look for processes running from unusual directories, or with unexpected parent processes.
print('Script executed. (Unusual process behavior detection logic to be implemented)')

Execution
python scripts/23_unusual_process_behavior.py

Goal
Detect suspicious or encoded command-line arguments.

Use Case
Execution of PowerShell obfuscation, execution of malicious scripts.

Python Code
# Placeholder for actual detection logic.
# This script would parse command-line logs (e.g., Sysmon Event ID 1)
# and apply heuristics or machine learning to detect unusual encoding, long strings of random characters,
# or suspicious arguments to legitimate executables.
print('Script executed. (Command line anomaly detection logic to be implemented)')

Execution
python scripts/24_command_line_anomaly.py

Goal
Identify rare, unusual, or known bot-related User-Agent strings in web traffic logs.

Use Case
Web access monitoring, detection of automated attacks or data exfiltration.

Python Code
# Placeholder for actual detection logic.
# This script would analyze web proxy or web server logs, parse User-Agent strings,
# and compare them against a baseline or a blacklist of suspicious UAs.
print('Script executed. (User-Agent anomaly detection logic to be implemented)')

Execution
python scripts/25_user_agent_anomaly_detector.py

Goal
Detect indicators of ransomware activity, such as rapid bulk file encryption or deletion.

Use Case
Early warning for ransomware outbreaks, post-infection investigation.

Python Code
# Placeholder for actual detection logic.
# This script would monitor file system events (e.g., creation, modification, deletion)
# for rapid changes, unusual file extensions, or a high volume of I/O operations from a single process.
print('Script executed. (Ransomware activity detection logic to be implemented)')

Execution
python scripts/26_ransomware_activity_detector.py

Goal
Detect internal network scanning activity (e.g., Nmap scans).

Use Case
Identification of reconnaissance activity, lateral movement.

Python Code
# Placeholder for actual detection logic.
# This script would analyze network flow data (NetFlow, sFlow) or firewall logs
# to identify rapid, sequential connection attempts to multiple internal IP addresses/ports.
print('Script executed. (Internal network scan detection logic to be implemented)')

Execution
python scripts/27_internal_network_scan_detector.py

Goal
List and identify suspicious or unauthorized browser extensions.

Use Case
Investigation of data exfiltration via browser, identifying malware-installed extensions.

Python Code
# Placeholder for actual detection logic.
# This script would typically interact with browser profiles or system files
# to enumerate installed extensions and compare them against a whitelist or known malicious extensions.
print('Script executed. (Malicious browser extension hunt logic to be implemented)')

Execution
python scripts/28_malicious_browser_extension_hunt.py

Goal
Detect unauthorized external file uploads or sharing activities.

Use Case
Data Loss Prevention (DLP) violation investigation.

Python Code
# Placeholder for actual detection logic.
# This script would analyze network proxy logs, firewall logs, or cloud service audit logs
# to identify uploads to unusual external destinations.
print('Script executed. (Unauthorized file share detection logic to be implemented)')

Execution
python scripts/29_unauthorized_file_share.py

Goal
Flag network traffic directed to known anonymization services (TOR, commercial VPN IPs).

Use Case
Identification of insider threats, advanced persistent threat (APT) activity, or policy violations.

Python Code
# Placeholder for actual detection logic.
# This script would analyze network flow data or DNS queries against a blacklist of
# known TOR exit nodes or VPN service IP ranges.
print('Script executed. (VPN/TOR exfiltration behavior detection logic to be implemented)')

Execution
python scripts/30_vpn_exfil_behavior.py

⚙️ How to Use
Terminal Execution
To execute any of the Python scripts, navigate to the root directory of this repository in your terminal and use the following command structure:

python scripts/<script_name>.py

Important: Ensure all necessary Python dependencies are installed (refer to requirements.txt) and that any required data files (e.g., CSV logs) are properly located within the data_samples/ directory as referenced by the scripts.

📂 Repository Structure
The repository is organized for clarity and ease of use:

Threat_Hunting_and_Remediation_Scripts/
├── scripts/                # Contains all Python threat hunting and remediation scripts
├── data_samples/           # Directory for sample log data used by the scripts (e.g., sysmon_logs.csv)
├── requirements.txt        # Lists all Python dependencies required for the scripts
└── README.md               # This README file

📞 Contact
For any questions, feedback, or collaborations, please feel free to reach out:

Author: Bharath Devulapalli

GitHub: https://github.com/Bharathkasyap

LinkedIn: https://www.linkedin.com/in/venkatadevu/
