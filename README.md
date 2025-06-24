# 🛡️ Python Script Library for Proactive Cyber Threat Hunting and Remediation

## 📖 Introduction
In today's evolving threat landscape, proactive threat hunting is indispensable for identifying and neutralizing sophisticated malicious activities that bypass traditional security defenses. This practice involves meticulously sifting through system and network logs, parsing vast amounts of event data, and identifying subtle behavioral anomalies indicative of compromise.

Python scripting empowers cybersecurity analysts and threat hunters to significantly enhance their capabilities by automating repetitive analysis tasks, rapidly parsing diverse log formats, enriching threat indicators, and even simulating attack or response scenarios. When combined with powerful Bash terminal execution, these scripts can be seamlessly deployed across endpoints or centrally managed for comprehensive investigative and remedial actions.

This repository features a curated collection of 30 Python scripts, meticulously categorized by common threat detection and response use cases. These scripts are designed to equip security professionals with practical tools to:

- Parse and analyze critical security logs (Sysmon, DNS, Event Logs, Email logs).
- Detect early indicators of compromise (IOCs).
- Monitor for advanced attack techniques (lateral movement, data exfiltration, persistence).
- Automate investigation and response to suspicious activities.

---

## 🚀 Script Catalog 

### 1. `detect_suspicious_processes.py`
**Goal**: Identify suspicious parent-child process relationships (e.g., winword.exe spawning cmd.exe).

**Use Case**: Post-phishing email analysis, investigation of macro-enabled document execution.

**Python Code**:
```python
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
```
**Execution**: `python scripts/1_detect_suspicious_processes.py`

---

### 2. `vulnerable_software_removal.py`
**Goal**: Automate the uninstallation of outdated or vulnerable software via WinRM.

**Use Case**: Post-vulnerability assessment remediation, rapid patch deployment.

**Python Code**:
```python
import winrm

session = winrm.Session('http://target-ip:5985/wsman', auth=('admin', 'password'))
command = r'wmic product where "Name like \'%Adobe%\'" get Name, Version'
result = session.run_cmd(command)
output = result.std_out.decode()

if "Adobe Reader XI" in output:
    uninstall_cmd = r'msiexec /x {AC76BA86-7AD7-1033-7B44-AB0000000001} /quiet'
    session.run_cmd(uninstall_cmd)
    print("✅ Uninstallation triggered for Adobe Reader XI.")
else:
    print("✅ No outdated Adobe Reader XI found.")
```
**Execution**: `python scripts/2_vulnerable_software_removal.py`

---

### 3. `virus_total_hash_checker.py`
**Goal**: Leverage the VirusTotal API to check the reputation of file hashes.

**Use Case**: Malware triage, initial assessment of suspicious file indicators.

**Python Code**:
```python
import requests

API_KEY = 'YOUR_VT_API_KEY'
hashes = ['44d88612fea8a8f36de82e1278abb02f']

print("--- VirusTotal Hash Check ---")
for h in hashes:
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": API_KEY}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        if 'data' in data and 'attributes' in data['data']:
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            print(f"Hash: {h} | Malicious Detections: {positives}")
        else:
            print(f"Hash: {h} | No analysis data found.")
    except requests.exceptions.RequestException as e:
        print(f"Error checking hash {h}: {e}")
```
**Execution**: `python scripts/3_virus_total_hash_checker.py`

---

### 4. `failed_login_brute_force.py`
**Goal**: Detect brute-force login attempts by identifying an excessive number of failed login events from a single source IP.

**Use Case**: Investigation of account lockouts, analysis of anomalous login patterns.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/login_data.csv')
grouped = df[df["status"] == "failed"].groupby("source_ip").size().reset_index(name='failed_attempts')
suspicious = grouped[grouped["failed_attempts"] > 10]

if not suspicious.empty:
    print("⚠️ Suspicious IPs with high failed login attempts:")
    print(suspicious)
else:
    print("✅ No suspicious brute-force attempts detected.")
```
**Execution**: `python scripts/4_failed_login_brute_force.py`

---

### 5. `usb_exfiltration_detector.py`
**Goal**: Identify large file transfers to USB devices.

**Use Case**: Investigation of insider threats or data loss prevention monitoring.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/event_logs_sample.csv')
usb_events = df[df["EventID"] == 4663]
usb_writes = usb_events[usb_events["ObjectName"].str.contains("E:\\", na=False)]
large_transfers = usb_writes[usb_writes["ObjectSize"] > 10 * 1024 * 1024]

if not large_transfers.empty:
    print("⚠️ Detected large file transfers to USB:")
    print(large_transfers[["UtcTime", "SubjectUserName", "ObjectName", "ObjectSize"]])
else:
    print("✅ No large USB file transfers detected.")
```
**Execution**: `python scripts/5_usb_exfiltration_detector.py`

---



# 🛡️ Python Script Library for Proactive Cyber Threat Hunting and Remediation

## 📖 Introduction
In today's evolving threat landscape, proactive threat hunting is indispensable for identifying and neutralizing sophisticated malicious activities that bypass traditional security defenses. This practice involves meticulously sifting through system and network logs, parsing vast amounts of event data, and identifying subtle behavioral anomalies indicative of compromise.

Python scripting empowers cybersecurity analysts and threat hunters to significantly enhance their capabilities by automating repetitive analysis tasks, rapidly parsing diverse log formats, enriching threat indicators, and even simulating attack or response scenarios. When combined with powerful Bash terminal execution, these scripts can be seamlessly deployed across endpoints or centrally managed for comprehensive investigative and remedial actions.

This repository features a curated collection of 30 Python scripts, meticulously categorized by common threat detection and response use cases. These scripts are designed to equip security professionals with practical tools to:

- Parse and analyze critical security logs (Sysmon, DNS, Event Logs, Email logs).
- Detect early indicators of compromise (IOCs).
- Monitor for advanced attack techniques (lateral movement, data exfiltration, persistence).
- Automate investigation and response to suspicious activities.

---

## 🚀 Script Catalog – Batch 1 (Scripts 1–10)

### 1. `detect_suspicious_processes.py`
**Goal**: Identify suspicious parent-child process relationships (e.g., winword.exe spawning cmd.exe).

**Use Case**: Post-phishing email analysis, investigation of macro-enabled document execution.

**Python Code**:
```python
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
```
**Execution**: `python scripts/1_detect_suspicious_processes.py`

---

### 2. `vulnerable_software_removal.py`
**Goal**: Automate the uninstallation of outdated or vulnerable software via WinRM.

**Use Case**: Post-vulnerability assessment remediation, rapid patch deployment.

**Python Code**:
```python
import winrm

session = winrm.Session('http://target-ip:5985/wsman', auth=('admin', 'password'))
command = r'wmic product where "Name like \'%Adobe%\'" get Name, Version'
result = session.run_cmd(command)
output = result.std_out.decode()

if "Adobe Reader XI" in output:
    uninstall_cmd = r'msiexec /x {AC76BA86-7AD7-1033-7B44-AB0000000001} /quiet'
    session.run_cmd(uninstall_cmd)
    print("✅ Uninstallation triggered for Adobe Reader XI.")
else:
    print("✅ No outdated Adobe Reader XI found.")
```
**Execution**: `python scripts/2_vulnerable_software_removal.py`

---

### 3. `virus_total_hash_checker.py`
**Goal**: Leverage the VirusTotal API to check the reputation of file hashes.

**Use Case**: Malware triage, initial assessment of suspicious file indicators.

**Python Code**:
```python
import requests

API_KEY = 'YOUR_VT_API_KEY'
hashes = ['44d88612fea8a8f36de82e1278abb02f']

print("--- VirusTotal Hash Check ---")
for h in hashes:
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": API_KEY}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        if 'data' in data and 'attributes' in data['data']:
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            print(f"Hash: {h} | Malicious Detections: {positives}")
        else:
            print(f"Hash: {h} | No analysis data found.")
    except requests.exceptions.RequestException as e:
        print(f"Error checking hash {h}: {e}")
```
**Execution**: `python scripts/3_virus_total_hash_checker.py`

---

### 4. `failed_login_brute_force.py`
**Goal**: Detect brute-force login attempts by identifying an excessive number of failed login events from a single source IP.

**Use Case**: Investigation of account lockouts, analysis of anomalous login patterns.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/login_data.csv')
grouped = df[df["status"] == "failed"].groupby("source_ip").size().reset_index(name='failed_attempts')
suspicious = grouped[grouped["failed_attempts"] > 10]

if not suspicious.empty:
    print("⚠️ Suspicious IPs with high failed login attempts:")
    print(suspicious)
else:
    print("✅ No suspicious brute-force attempts detected.")
```
**Execution**: `python scripts/4_failed_login_brute_force.py`

---

### 5. `usb_exfiltration_detector.py`
**Goal**: Identify large file transfers to USB devices.

**Use Case**: Investigation of insider threats or data loss prevention monitoring.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/event_logs_sample.csv')
usb_events = df[df["EventID"] == 4663]
usb_writes = usb_events[usb_events["ObjectName"].str.contains("E:\\", na=False)]
large_transfers = usb_writes[usb_writes["ObjectSize"] > 10 * 1024 * 1024]

if not large_transfers.empty:
    print("⚠️ Detected large file transfers to USB:")
    print(large_transfers[["UtcTime", "SubjectUserName", "ObjectName", "ObjectSize"]])
else:
    print("✅ No large USB file transfers detected.")
```
**Execution**: `python scripts/5_usb_exfiltration_detector.py`

---

<details>
<summary><strong>6. cve_auto_lookup.py</strong></summary>

**Goal**
Retrieve detailed Common Vulnerabilities and Exposures (CVE) information from the National Vulnerability Database (NVD) API.

**When to Use**
During patch management research, vulnerability assessment, threat intelligence enrichment.

**How to Execute**
```bash
python scripts/6_cve_auto_lookup.py
```

**Python Code**
```python
import requests

cve_id = "CVE-2023-23397"
url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"

try:
    resp = requests.get(url)
    resp.raise_for_status()
    data = resp.json()

    cve_item = data.get("result", {}).get("CVE_Items", [])[0]
    desc = cve_item["cve"]["description"]["description_data"][0]["value"]
    severity = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "N/A")

    print(f"--- CVE Information for {cve_id} ---")
    print(f"Severity: {severity}")
    print(f"Description: {desc}")
except Exception as e:
    print(f"Error: {e}")
```
</details>

<details>
<summary><strong>7. dns_tunneling_detector.py</strong></summary>

**Goal**
Detect potential DNS tunneling using TXT records.

**When to Use**
During C2 beaconing investigation, data exfiltration via DNS.

**How to Execute**
```bash
python scripts/7_dns_tunneling_detector.py
```

**Python Code**
```python
import pandas as pd
df = pd.read_csv('../data_samples/dns_logs.csv')
suspicious = df[(df["query_type"] == "TXT") & (df["query_name"].str.len() > 100)]

if not suspicious.empty:
    print("⚠️ Suspicious DNS tunneling candidates detected:")
    print(suspicious[["timestamp", "client_ip", "query_name"]])
else:
    print("✅ No suspicious DNS tunneling detected.")
```
</details>

<details>
<summary><strong>8. network_port_scanner.py</strong></summary>

**Goal**
Perform basic port scan to detect open ports.

**When to Use**
Validating network exposure, unauthorized services audit.

**How to Execute**
```bash
python scripts/8_network_port_scanner.py
```

**Python Code**
```python
import socket
target = '192.168.1.100'
ports = [21, 22, 80, 443]

for port in ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is OPEN")
        sock.close()
    except Exception as e:
        print(e)
```
</details>

<details>
<summary><strong>9. patch_compliance_checker.py</strong></summary>

**Goal**
Check for critical Windows KB patches on the system.

**When to Use**
Patch audit, compliance check.

**How to Execute**
```bash
python scripts/9_patch_compliance_checker.py
```

**Python Code**
```python
import subprocess
required_kbs = ["KB5027215", "KB5034441"]
output = subprocess.getoutput("wmic qfe get HotFixID")

for kb in required_kbs:
    if kb in output:
        print(f"✅ {kb} is installed.")
    else:
        print(f"❌ {kb} is missing.")
```
</details>

<details>
<summary><strong>10. rdp_session_monitor.py</strong></summary>

**Goal**
Monitor successful RDP login events.

**When to Use**
Post-brute-force login investigation, remote access monitoring.

**How to Execute**
```bash
python scripts/10_rdp_session_monitor.py
```

**Python Code**
```python
import pandas as pd
df = pd.read_csv('../data_samples/login_data.csv')
rdp_sessions = df[(df["LogonType"] == "10") & (df["Status"] == "success")]

if not rdp_sessions.empty:
    print("⚠️ RDP sessions found:")
    print(rdp_sessions[["timestamp", "source_ip", "user"]])
else:
    print("✅ No RDP sessions detected.")
```
</details>


### 11. `detect_persistence_registry_keys.py`
**Goal**: Identify registry keys commonly used for persistence (e.g., Run, RunOnce).

**Use Case**: Hunt for malware maintaining persistence via Windows registry modifications.

**Python Code**:
```python
import pandas as pd

# Simulate exported registry entries
df = pd.read_csv('../data_samples/registry_export.csv')

suspicious_keys = [
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
]

matches = df[df["RegistryPath"].isin(suspicious_keys)]

if not matches.empty:
    print("⚠️ Persistence-related registry keys detected:")
    print(matches[["RegistryPath", "ValueName", "ValueData"]])
else:
    print("✅ No suspicious registry keys found.")
```
**Execution**: `python scripts/11_detect_persistence_registry_keys.py`

---

### 12. `scripted_mimikatz_artifact_scan.py`
**Goal**: Detect presence of mimikatz signatures or related artifacts.

**Use Case**: Threat hunting for credential dumping attempts.

**Python Code**:
```python
import os

suspicious_terms = ["mimikatz", "sekurlsa", "kerberos", "pth"]

for root, dirs, files in os.walk("C:\\"):
    for file in files:
        try:
            path = os.path.join(root, file)
            with open(path, "r", errors="ignore") as f:
                content = f.read().lower()
                if any(term in content for term in suspicious_terms):
                    print(f"⚠️ Mimikatz-related term found in {path}")
        except:
            continue
```
**Execution**: `python scripts/12_scripted_mimikatz_artifact_scan.py`

---

### 13. `scan_for_unusual_scheduled_tasks.py`
**Goal**: Enumerate scheduled tasks and highlight uncommon entries.

**Use Case**: Detection of persistence mechanisms and malicious scripts.

**Python Code**:
```python
import subprocess
import re

print("--- Scheduled Task Scan ---")
output = subprocess.getoutput("schtasks /query /fo LIST /v")

suspicious_entries = re.findall(r"Task To Run:\s+(.+)", output)

for task in suspicious_entries:
    if any(keyword in task.lower() for keyword in ["powershell", "cmd", "vbs", ".bat", ".ps1"]):
        print(f"⚠️ Suspicious task detected: {task}")
```
**Execution**: `python scripts/13_scan_for_unusual_scheduled_tasks.py`

---

### 14. `detect_remote_access_tools.py`
**Goal**: Scan running processes for known RATs (Remote Access Tools).

**Use Case**: Detect active usage of unauthorized remote control tools.

**Python Code**:
```python
import psutil

rat_indicators = ["anydesk", "teamviewer", "vnc", "remcos", "radmin"]

print("--- Remote Access Tool Detection ---")
for proc in psutil.process_iter(['pid', 'name']):
    if any(rat in proc.info['name'].lower() for rat in rat_indicators):
        print(f"⚠️ Potential RAT running: {proc.info['name']} (PID: {proc.info['pid']})")
```
**Execution**: `python scripts/14_detect_remote_access_tools.py`

---

### 15. `office_macro_analyzer.py`
**Goal**: Check MS Office documents for embedded macros.

**Use Case**: Pre-delivery inspection of files, phishing document analysis.

**Python Code**:
```python
import oletools.olevba3 as olevba
import os

doc = olevba.VBA_Parser("../data_samples/macro_enabled.doc")
if doc.detect_vba_macros():
    print("⚠️ Macros found in Office document!")
    for (filename, stream_path, vba_filename, vba_code) in doc.extract_macros():
        print(f"Macro from {vba_filename}:\n{vba_code[:200]}...")
else:
    print("✅ No macros found.")
```
**Execution**: `python scripts/15_office_macro_analyzer.py`

---

### 16. `lateral_movement_event_monitor.py`
**Goal**: Detect suspicious use of PsExec, WMI, and PowerShell remoting.

**Use Case**: Identify attacker movement across internal network.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/sysmon_events.csv')

lateral_tools = ["psexec", "wmic", "powershell -enc"]
df["CommandLine"] = df["CommandLine"].str.lower()

matches = df[df["CommandLine"].str.contains('|'.join(lateral_tools), na=False)]

if not matches.empty:
    print("⚠️ Lateral movement attempts found:")
    print(matches[["UtcTime", "Image", "CommandLine"]])
else:
    print("✅ No signs of lateral movement.")
```
**Execution**: `python scripts/16_lateral_movement_event_monitor.py`

---

### 17. `external_data_upload_monitor.py`
**Goal**: Detect high-volume or unusual outbound traffic patterns.

**Use Case**: Data exfiltration detection, breach investigation.

**Python Code**:
```python
import pandas as pd

network_logs = pd.read_csv("../data_samples/network_activity.csv")
suspicious_traffic = network_logs[network_logs["dest_port"] == 443]
suspicious_traffic = suspicious_traffic[suspicious_traffic["bytes_out"] > 10 * 1024 * 1024]

if not suspicious_traffic.empty:
    print("⚠️ Possible exfiltration over HTTPS detected:")
    print(suspicious_traffic[["timestamp", "src_ip", "dest_ip", "bytes_out"]])
else:
    print("✅ No unusual outbound traffic.")
```
**Execution**: `python scripts/17_external_data_upload_monitor.py`

---

### 18. `dns_c2_beaconing_detector.py`
**Goal**: Detect beaconing patterns to DGA (domain generation algorithm) or suspicious domains.

**Use Case**: Command-and-Control (C2) detection.

**Python Code**:
```python
import pandas as pd

logs = pd.read_csv("../data_samples/dns_logs.csv")
beaconing = logs[logs['query_name'].str.contains("xyz", na=False)]

if not beaconing.empty:
    print("⚠️ DNS beaconing behavior detected:")
    print(beaconing[["timestamp", "client_ip", "query_name"]])
else:
    print("✅ No beaconing activity detected.")
```
**Execution**: `python scripts/18_dns_c2_beaconing_detector.py`

---

### 19. `shadow_admin_privilege_audit.py`
**Goal**: Identify users with excessive privileges not formally tracked.

**Use Case**: Privilege audit and lateral movement risk mitigation.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv("../data_samples/user_rights.csv")
elevated = df[df["role"].str.contains("admin|domain", case=False, na=False)]

print("--- Shadow Admin Audit ---")
print(elevated[["username", "role", "group_membership"]])
```
**Execution**: `python scripts/19_shadow_admin_privilege_audit.py`

---

### 20. `power_shell_encoded_command_detector.py`
**Goal**: Detect use of base64-encoded PowerShell commands.

**Use Case**: Obfuscation detection, malware execution analysis.

**Python Code**:
```python
import pandas as pd

log_data = pd.read_csv("../data_samples/powershell_logs.csv")
encoded = log_data[log_data["CommandLine"].str.contains("-enc", case=False, na=False)]

if not encoded.empty:
    print("⚠️ Encoded PowerShell commands detected:")
    print(encoded[["timestamp", "user", "CommandLine"]])
else:
    print("✅ No suspicious PowerShell encoding usage found.")
```
**Execution**: `python scripts/20_power_shell_encoded_command_detector.py`

---


### 21. `phishing_email_indicator_parser.py`
**Goal**: Parse email logs for phishing indicators like suspicious subjects and sender domains.

**Use Case**: Investigation of reported phishing emails.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/email_logs.csv')

phishing_subjects = ['verify account', 'suspended', 'password expired', 'urgent action']
phishing_senders = ['mail.ru', 'protonmail.com', 'outlook.phish.net']

suspicious = df[
    df['subject'].str.lower().str.contains('|'.join(phishing_subjects), na=False) |
    df['sender_domain'].str.lower().isin(phishing_senders)
]

print(suspicious[['timestamp', 'sender', 'subject', 'spf_status']])
```
**Execution**: `python scripts/21_phishing_email_indicator_parser.py`

---

### 22. `beaconing_domain_hunt.py`
**Goal**: Detect C2 beaconing through frequent outbound domain queries.

**Use Case**: C2 activity or malware call-back detection.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/dns_logs.csv')
grouped = df.groupby(['client_ip', 'query_name']).size().reset_index(name='count')

beacon_candidates = grouped[grouped['count'] > 100]
print(beacon_candidates)
```
**Execution**: `python scripts/22_beaconing_domain_hunt.py`

---

### 23. `unusual_process_behavior.py`
**Goal**: Detect anomalies in process execution, like svchost.exe running outside of system32.

**Use Case**: Masquerading or process injection detection.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/sysmon_logs.csv')
unusual = df[(df['Image'].str.endswith('svchost.exe')) & (~df['Image'].str.contains('system32', case=False))]

print(unusual[['UtcTime', 'Image', 'CommandLine']])
```
**Execution**: `python scripts/23_unusual_process_behavior.py`

---

### 24. `command_line_anomaly.py`
**Goal**: Flag suspicious command-line use (e.g., encoded PowerShell, curl, wget).

**Use Case**: Command execution and malware delivery analysis.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/sysmon_logs.csv')
bad_patterns = ['curl', 'wget', 'bitsadmin', 'invoke-webrequest', 'powershell -enc']

cmd_matches = df[df['CommandLine'].str.lower().str.contains('|'.join(bad_patterns), na=False)]
print(cmd_matches[['UtcTime', 'Image', 'CommandLine']])
```
**Execution**: `python scripts/24_command_line_anomaly.py`

---

### 25. `user_agent_anomaly_detector.py`
**Goal**: Detect non-browser user agents that may be bots or scrapers.

**Use Case**: Abnormal web access behavior analysis.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/web_proxy_logs.csv')
known_agents = ['chrome', 'firefox', 'edge', 'safari']
df['ua_lower'] = df['user_agent'].str.lower()
suspicious_agents = df[~df['ua_lower'].str.contains('|'.join(known_agents))]

print(suspicious_agents[['timestamp', 'src_ip', 'user_agent']])
```
**Execution**: `python scripts/25_user_agent_anomaly_detector.py`

---

### 26. `ransomware_activity_detector.py`
**Goal**: Identify ransomware behavior by detecting mass file changes/extensions.

**Use Case**: Initial detection of file encryption attacks.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/file_events.csv')
df['ext'] = df['FileName'].str.extract(r'(\.\w+)$')
suspicious_ext = ['.locky', '.crypted', '.pay2decrypt', '.enc']
matches = df[df['ext'].isin(suspicious_ext)]

print(matches[['UtcTime', 'FileName', 'ProcessName']])
```
**Execution**: `python scripts/26_ransomware_activity_detector.py`

---

### 27. `internal_network_scan_detector.py`
**Goal**: Detect internal scanning behavior (e.g., Nmap).

**Use Case**: Identify lateral movement and unauthorized network discovery.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/network_events.csv')
port_scans = df.groupby(['source_ip', 'dest_port']).size().reset_index(name='count')
scan_counts = port_scans.groupby('source_ip').count()
suspicious = scan_counts[scan_counts['dest_port'] > 50]
print(suspicious)
```
**Execution**: `python scripts/27_internal_network_scan_detector.py`

---

### 28. `malicious_browser_extension_hunt.py`
**Goal**: Identify risky Chrome extensions based on permissions.

**Use Case**: Browser-based data theft or adware analysis.

**Python Code**:
```python
import os
import json

ext_dir = 'C:/Users/User/AppData/Local/Google/Chrome/User Data/Default/Extensions'
for ext_id in os.listdir(ext_dir):
    for version in os.listdir(os.path.join(ext_dir, ext_id)):
        manifest_path = os.path.join(ext_dir, ext_id, version, 'manifest.json')
        try:
            with open(manifest_path, 'r') as file:
                manifest = json.load(file)
                print(f"Extension: {manifest.get('name')} | ID: {ext_id}")
        except:
            continue
```
**Execution**: `python scripts/28_malicious_browser_extension_hunt.py`

---

### 29. `unauthorized_file_share.py`
**Goal**: Detect uploads to unauthorized cloud storage providers.

**Use Case**: Insider threat and DLP monitoring.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/web_proxy_logs.csv')
file_sharing = ['dropbox.com', 'drive.google.com', 'wetransfer.com']
suspicious = df[df['host'].str.contains('|'.join(file_sharing), na=False)]
print(suspicious[['timestamp', 'src_ip', 'host', 'url']])
```
**Execution**: `python scripts/29_unauthorized_file_share.py`

---

### 30. `vpn_exfil_behavior.py`
**Goal**: Flag data exfiltration over TOR/VPN endpoints.

**Use Case**: Monitoring for hidden outbound tunnels.

**Python Code**:
```python
import pandas as pd

df = pd.read_csv('../data_samples/firewall_logs.csv')
vpn_ips = ['185.220.101.1', '172.105.28.93']
matches = df[df['dest_ip'].isin(vpn_ips)]

print(matches[['timestamp', 'src_ip', 'dest_ip', 'bytes_sent']])
```
**Execution**: `python scripts/30_vpn_exfil_behavior.py

























# 🛡️ Threat Hunting with Python – Script Library

## 📖 Introduction
Threat hunting is a proactive security practice where analysts search through systems and networks to identify malicious activity that evades traditional security solutions. It involves querying logs, parsing event data, and identifying behavioral anomalies.

Python scripting allows threat hunters to automate repetitive analysis, parse logs quickly, enrich indicators, and even simulate attacks or responses. Combined with Bash terminal execution, these scripts can be deployed across endpoints or run centrally for investigative tasks.

This repository contains **30 Python scripts** categorized under threat detection use cases, designed to help analysts:

- Parse Sysmon, DNS, Event, and Email logs
- Detect early indicators of compromise (IOCs)
- Monitor for lateral movement, data exfiltration, and persistence
- Automate investigation of suspicious activity

---


## How to Use from Terminal

```bash
python scripts/<script_name>.py
```

Ensure dependencies are installed and data files are located in the `data_samples/` directory.

---

## Contact

Author: Bharath Devulapalli  
GitHub: https://github.com/Bharathkasyap  
LinkedIn: https://www.linkedin.com/in/venkatadevu/
