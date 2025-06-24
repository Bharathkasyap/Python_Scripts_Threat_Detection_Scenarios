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

## 🚀 Script Catalog – Batch 2 (Scripts 6–10)

(Already added above. Now continuing with Batch 3 in the next update...)

## 🚀 Script Catalog – Batch 3 (Scripts 11–20)



























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

### 6–10 → Coming in Batch 2









## Python Script Library for Proactive Cyber Threat Hunting and Remediation

### 📖 Introduction
In today's evolving threat landscape, proactive threat hunting is indispensable for identifying and neutralizing sophisticated malicious activities that bypass traditional security defenses. Python scripting enhances these capabilities by automating analysis, parsing logs, and simulating scenarios.

This repository contains 30 Python scripts, grouped into 3 batches, for use in real-world threat hunting and remediation.

---

## 📂 Batch 2: Scripts 6–10

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

## Scripts


<details>
<summary><strong>1. detect_suspicious_processes.py</strong></summary>

**Goal**  
Detect suspicious parent-child processes (e.g., winword.exe → cmd.exe)

**When to Use**  
After phishing emails or macro document usage


**Python Code**
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

**How to Execute**  
```
python scripts/1_detect_suspicious_processes.py
```

</details>

<details>
<summary><strong>2. vulnerable_software_removal.py</strong></summary>

**Goal**  
Uninstall outdated software via WinRM

**When to Use**  
Post vulnerability assessment

**How to Execute**  
```
python scripts/2_vulnerable_software_removal.py
```

**Python Code**
```python
import winrm

session = winrm.Session('http://target-ip:5985/wsman', auth=('admin', 'password'))
command = r'wmic product where "Name like \'%Adobe%\'" get Name, Version'
result = session.run_cmd(command)
output = result.std_out.decode()

if "Adobe Reader XI" in output:
    uninstall_cmd = r'msiexec /x {AC76BA86-7AD7-1033-7B44-AB0000000001} /quiet'
    session.run_cmd(uninstall_cmd)
    print("✅ Uninstallation triggered.")
else:
    print("✅ No outdated software found.")

```

</details>

<details>
<summary><strong>3. virus_total_hash_checker.py</strong></summary>

**Goal**  
Check hashes with VirusTotal API

**When to Use**  
During malware triage

**How to Execute**  
```
python scripts/3_virus_total_hash_checker.py
```

**Python Code**
```python
import requests

API_KEY = 'YOUR_VT_API_KEY'
hashes = ['44d88612fea8a8f36de82e1278abb02f']

for h in hashes:
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": API_KEY}
    resp = requests.get(url, headers=headers)
    data = resp.json()
    positives = data['data']['attributes']['last_analysis_stats']['malicious']
    print(f"Hash: {h} | Malicious Detections: {positives}")

```

</details>

<details>
<summary><strong>4. failed_login_brute_force.py</strong></summary>

**Goal**  
Detect brute-force login attempts

**When to Use**  
Account lockout or failed logins observed

**How to Execute**  
```
python scripts/4_failed_login_brute_force.py
```

**Python Code**
```python
import pandas as pd

df = pd.read_csv('../data_samples/login_data.csv')
grouped = df[df["status"] == "failed"].groupby("source_ip").count()
suspicious = grouped[grouped["username"] > 10]
print("Suspicious IPs with high failed attempts:\n", suspicious)

```

</details>

<details>
<summary><strong>5. usb_exfiltration_detector.py</strong></summary>

**Goal**  
Detect large file transfers to USB

**When to Use**  
Suspected insider threat

**How to Execute**  
```
python scripts/5_usb_exfiltration_detector.py
```

**Python Code**
```python
import pandas as pd

df = pd.read_csv('../data_samples/event_logs_sample.csv')
usb_events = df[df["EventID"] == 4663]
usb_writes = usb_events[usb_events["ObjectName"].str.contains("E:\\", na=False)]
large_transfers = usb_writes[usb_writes["ObjectSize"] > 10 * 1024 * 1024]

print("Detected large file transfers to USB:\n", large_transfers[["UtcTime", "SubjectUserName", "ObjectName", "ObjectSize"]])

```

</details>

<details>
<summary><strong>6. cve_auto_lookup.py</strong></summary>

**Goal**  
Get CVE info from NVD

**When to Use**  
During patch research

**How to Execute**  
```
python scripts/6_cve_auto_lookup.py
```

**Python Code**
```python
import requests

cve_id = "CVE-2023-23397"
url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
resp = requests.get(url)
data = resp.json()
cve = data["result"]["CVE_Items"][0]
desc = cve["cve"]["description"]["description_data"][0]["value"]
severity = cve["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]

print(f"{cve_id}: {severity}\nDescription: {desc}")

```

</details>

<details>
<summary><strong>7. dns_tunneling_detector.py</strong></summary>

**Goal**  
Detect encoded DNS requests

**When to Use**  
Beaconing or exfiltration via DNS suspected

**How to Execute**  
```
python scripts/7_dns_tunneling_detector.py
```

**Python Code**
```python
import pandas as pd

df = pd.read_csv('../data_samples/dns_logs.csv')
suspicious = df[(df["query_type"] == "TXT") & (df["query_name"].str.len() > 100)]
print("Suspicious DNS tunneling candidates:\n", suspicious[["timestamp", "client_ip", "query_name", "query_type"]])

```

</details>

<details>
<summary><strong>8. network_port_scanner.py</strong></summary>

**Goal**  
Scan host for open ports

**When to Use**  
Validate exposure or unauthorized services

**How to Execute**  
```
python scripts/8_network_port_scanner.py
```

**Python Code**
```python
import socket

target = '192.168.1.100'
ports = [21, 22, 23, 80, 443, 3389]

for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((target, port))
    if result == 0:
        print(f"Port {port} is OPEN on {target}")
    sock.close()

```

</details>

<details>
<summary><strong>9. patch_compliance_checker.py</strong></summary>

**Goal**  
Check for missing Windows KBs

**When to Use**  
Audit patch status

**How to Execute**  
```
python scripts/9_patch_compliance_checker.py
```

**Python Code**
```python
import subprocess

required_kbs = ["KB5027215", "KB5034441"]
output = subprocess.getoutput("wmic qfe get HotFixID")

for kb in required_kbs:
    if kb in output:
        print(f"{kb} is installed.")
    else:
        print(f"{kb} is MISSING!")

```

</details>

<details>
<summary><strong>10. rdp_session_monitor.py</strong></summary>

**Goal**  
Detect suspicious RDP logons

**When to Use**  
After brute-force or off-hour access

**How to Execute**  
```
python scripts/10_rdp_session_monitor.py
```

**Python Code**
```python
import pandas as pd

df = pd.read_csv('../data_samples/login_data.csv')
rdp_sessions = df[(df["LogonType"] == "10") & (df["Status"] == "success")]
print("Detected successful RDP sessions:\n", rdp_sessions[["timestamp", "source_ip", "user"]])

```

</details>

<details>
<summary><strong>11. suspicious_powershell_usage.py</strong></summary>

**Goal**  
Detect obfuscated PowerShell

**When to Use**  
Phishing delivery or macro usage

**How to Execute**  
```
python scripts/11_suspicious_powershell_usage.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>12. malicious_domain_checker.py</strong></summary>

**Goal**  
Flag malicious domain queries

**When to Use**  
After IOC alert or phishing email

**How to Execute**  
```
python scripts/12_malicious_domain_checker.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>13. browser_history_analyzer.py</strong></summary>

**Goal**  
Extract browser activity

**When to Use**  
Check for phishing or malicious links

**How to Execute**  
```
python scripts/13_browser_history_analyzer.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>14. process_injection_detector.py</strong></summary>

**Goal**  
Detect injection techniques

**When to Use**  
When LSASS tampering is suspected

**How to Execute**  
```
python scripts/14_process_injection_detector.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>15. mimikatz_detection_sysmon.py</strong></summary>

**Goal**  
Detect Mimikatz behavior

**When to Use**  
Credential dump detection

**How to Execute**  
```
python scripts/15_mimikatz_detection_sysmon.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>16. anomalous_login_time.py</strong></summary>

**Goal**  
Detect off-hours logins

**When to Use**  
Compromised account behavior

**How to Execute**  
```
python scripts/16_anomalous_login_time.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>17. geoip_login_mismatch.py</strong></summary>

**Goal**  
Detect logins from distant locations

**When to Use**  
Geo anomaly detection

**How to Execute**  
```
python scripts/17_geoip_login_mismatch.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>18. scheduled_task_abuse.py</strong></summary>

**Goal**  
Find malicious scheduled tasks

**When to Use**  
Persistence hunting

**How to Execute**  
```
python scripts/18_scheduled_task_abuse.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>19. suspicious_registry_mods.py</strong></summary>

**Goal**  
Find registry persistence

**When to Use**  
Persistence or privilege escalation

**How to Execute**  
```
python scripts/19_suspicious_registry_mods.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>20. service_creation_hunt.py</strong></summary>

**Goal**  
Detect malicious service creation

**When to Use**  
Lateral movement

**How to Execute**  
```
python scripts/20_service_creation_hunt.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>21. phishing_email_indicator_parser.py</strong></summary>

**Goal**  
Parse phishing subject/domains

**When to Use**  
User-reported phishing emails

**How to Execute**  
```
python scripts/21_phishing_email_indicator_parser.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>22. beaconing_domain_hunt.py</strong></summary>

**Goal**  
Detect beaconing traffic

**When to Use**  
C2 or malware behavior suspected

**How to Execute**  
```
python scripts/22_beaconing_domain_hunt.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>23. unusual_process_behavior.py</strong></summary>

**Goal**  
Detect non-standard execution paths

**When to Use**  
Masquerading or DLL injection

**How to Execute**  
```
python scripts/23_unusual_process_behavior.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>24. command_line_anomaly.py</strong></summary>

**Goal**  
Detect suspicious command line usage

**When to Use**  
Execution of encoded scripts

**How to Execute**  
```
python scripts/24_command_line_anomaly.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>25. user_agent_anomaly_detector.py</strong></summary>

**Goal**  
Identify rare/bot user agents

**When to Use**  
Web access monitoring

**How to Execute**  
```
python scripts/25_user_agent_anomaly_detector.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>26. ransomware_activity_detector.py</strong></summary>

**Goal**  
Detect bulk file encryption

**When to Use**  
Ransomware outbreak investigation

**How to Execute**  
```
python scripts/26_ransomware_activity_detector.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>27. internal_network_scan_detector.py</strong></summary>

**Goal**  
Detect internal Nmap scans

**When to Use**  
Reconnaissance activity

**How to Execute**  
```
python scripts/27_internal_network_scan_detector.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>28. malicious_browser_extension_hunt.py</strong></summary>

**Goal**  
List suspicious browser extensions

**When to Use**  
Exfiltration or malware via browser

**How to Execute**  
```
python scripts/28_malicious_browser_extension_hunt.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>29. unauthorized_file_share.py</strong></summary>

**Goal**  
Detect external file uploads

**When to Use**  
DLP violation investigation

**How to Execute**  
```
python scripts/29_unauthorized_file_share.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>

<details>
<summary><strong>30. vpn_exfil_behavior.py</strong></summary>

**Goal**  
Flag traffic to TOR/VPN IPs

**When to Use**  
Insider threat or APT behavior

**How to Execute**  
```
python scripts/30_vpn_exfil_behavior.py
```

**Python Code**
```python
# Actual detection logic here...
print('Script executed')
```

</details>


---

## How to Use from Terminal

```bash
python scripts/<script_name>.py
```

Ensure dependencies are installed and data files are located in the `data_samples/` directory.

---

## Directory Structure

```
Threat_Hunting_and_Remediation_Scripts/
├── scripts/
├── data_samples/
├── requirements.txt
└── README.md
```

---

## Contact

Author: Bharath Devulapalli  
GitHub: https://github.com/Bharathkasyap  
LinkedIn: https://www.linkedin.com/in/venkatadevu/
