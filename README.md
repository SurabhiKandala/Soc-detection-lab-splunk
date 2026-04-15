# 🔐 SOC Detection Lab — Splunk, Sysmon & MITRE ATT&CK

## 📌 Overview
This project demonstrates a Security Operations Center (SOC) home lab built to simulate and detect brute-force attacks and post-compromise behavior using Splunk SIEM.

The focus is not just on detecting failed logins, but understanding attacker behavior after successful access.

---

## 🏗️ Lab Architecture

- **Kali Linux** → Attacker machine  
- **Windows 10** → Victim machine  
- **Ubuntu Server** → Splunk Enterprise (SIEM)  

- Logs forwarded using **Splunk Universal Forwarder**
- Endpoint visibility enhanced using **Sysmon**

---

## ⚙️ Data Sources

- Windows Security Logs  
- Sysmon Logs  
- Splunk Index: `main`

---

## 🔍 Attack Simulation

Simulated brute-force login attempts using Kali Linux.

### Events generated:
- **4625** → Failed login attempts  
- **4624** → Successful login  
- **4688** → Process creation  

---

## 🧠 Detection Logic

Instead of treating events individually, detection was based on behavioral sequences:

`Multiple failed logins → Successful login → Command execution`

---

## 📊 Key SPL Queries

### 🔹 Failed + Successful Login Correlation

```spl
index=main (EventCode=4625 OR EventCode=4624)
| eval failed=if(EventCode=4625,1,0)
| eval success=if(EventCode=4624,1,0)
| stats sum(failed) as failed_attempts sum(success) as success_logins by Account_Name
| where failed_attempts > 5 AND success_logins > 0
🔹 Suspicious Process Execution
index=main EventCode=4688
| search New_Process_Name="*cmd.exe*" OR New_Process_Name="*powershell.exe*"
| stats count by New_Process_Name, Account_Name
🚨 Alerting
Created scheduled alerts in Splunk
Trigger condition:
Number of results > 0
Frequency: every 15 minutes

Alerts detect:

Suspicious command execution
Post-compromise activity
📈 Dashboards

Built dashboards to visualize:

Failed login trends
Targeted accounts
Process activity
Attack frequency over time
🎯 Key Insight

The attack was not obvious in failed logins.

It became clear only after:

A successful login
Followed by command execution

This shifted detection from:

Event-based monitoring
To behavioral analysis
🧪 Validation
Simulated full attack lifecycle
Verified detection logic end-to-end
Confirmed alert triggering
🧩 MITRE ATT&CK Mapping
T1110 — Brute Force (Credential Access)
📸 Screenshots

Screenshots will be added for:

Lab architecture
Detection queries
Brute-force correlation
Suspicious process execution
Alert trigger history
🚀 Skills Demonstrated
SIEM (Splunk)
Log analysis
Threat detection
Event correlation
Blue team fundamentals
MITRE ATT&CK mapping
🔚 Conclusion

This project demonstrates how real SOC detection goes beyond isolated logs and focuses on behavior patterns.

Attackers operate in sequences — and detection must do the same.
