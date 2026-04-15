
## 🚨 Incident Report — Brute Force Attack & Post-Compromise Activity Detection

### 📌 Summary

A simulated brute-force attack was conducted in a controlled SOC lab environment. The attack initially appeared as repeated failed login attempts, but further analysis revealed successful authentication followed by suspicious command execution, indicating potential account compromise.

---

### 🕒 Timeline of Events

* Multiple failed login attempts detected (Event ID 4625)
* Successful login observed for the same account (Event ID 4624)
* Immediate execution of command-line processes (Event ID 4688)
* Splunk alert triggered based on detection logic

---

### 🧠 Detection Logic

The detection was based on correlating authentication and process activity:

* Failed logins (4625)
* Successful login (4624)
* Process execution (4688)

Detection sequence:

```
4625 → 4624 → 4688
```

This sequence indicates a transition from brute-force attempts to post-compromise behavior.

---

### 🔍 Investigation Findings

#### 🔹 Authentication Analysis

* Repeated failed login attempts targeting a single user account
* A successful login following multiple failures
* Indicates possible credential compromise

#### 🔹 Process Activity Analysis

* Execution of `cmd.exe` and `powershell.exe`
* Activity occurred immediately after successful login
* Suggests potential attacker interaction or command execution

---

### 🚨 Alerting

A scheduled alert was configured in Splunk with the following conditions:

* Trigger condition: Number of results > 0
* Frequency: Every 15 minutes

The alert successfully detected:

* Suspicious command execution
* Post-compromise activity

---

### 📊 Evidence

* Login correlation results (failed vs successful logins)
* Process execution logs (cmd.exe, PowerShell)
* Alert trigger history
* Dashboard visualizations

---

### 🧪 Validation

The attack scenario was simulated end-to-end to validate detection accuracy:

* Brute-force attack executed from attacker machine
* Logs successfully ingested into Splunk
* Detection queries identified suspicious behavior
* Alert triggered as expected

---

### 🧩 MITRE ATT&CK Mapping

* **T1110 — Brute Force (Credential Access)**

---

### 🎯 Key Insight

The attack did not stand out when analyzing failed logins alone.

It became visible only after:

* A successful login
* Followed by command execution

This highlights the importance of:

* Correlating multiple events
* Focusing on behavior rather than isolated logs

---

### 🔚 Conclusion

This incident demonstrates how effective SOC detection relies on identifying behavior patterns rather than individual events.

By correlating authentication logs with process activity, it is possible to detect potential compromises that would otherwise appear as normal system activity.

Attackers operate in sequences — and detection must do the same.
