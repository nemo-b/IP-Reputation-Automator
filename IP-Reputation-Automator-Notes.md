# **IP-Reputation-Automator: Intelligence Orchestration & Automation**

> **Objective:** To automate the high-frequency task of IP triage by correlating behavioral data (AbuseIPDB) with reputational telemetry (VirusTotal) into a unified analyst dashboard.

---

## **📂  Project Roadmap & Progress**

### **Phase 0: Assumed Baseline (Guaranteed)**
_Focus: The foundational environment of a security developer._

- [x]  **OS Environment:** Currently operating under **Linux Mint 22** (Standardized dev environment).
- [x]  **- **Virtualization & Isolation:** Leveraged Python **Virtual Environments (venv)** to kill OS-level dependency conflicts before they started.
- [x]  - **Secret Management:** Strictly using **.env** structures. No hardcoded API keys allowed—OPSEC is a priority.

---
### **Phase 1: Environment Orchestration & Base Logic**

- [x]  **Logic Foundation:** Established the core `ThreatEnricher` class to handle AbuseIPDB API requests.
- [x]  **Environment Hardening:** - Successfully wrestled with **PEP 668** errors by forcing all project-specific libraries into the venv.
- [x]  **Initial API Security:** - Verified `.env` loading is stable. Credentials are safe and sound.

> **Key Question:** _Can I build a secure script that interacts with external threat intelligence without exposing my own credentials?_

---
### **Phase 2: Data Correlation & Bulk Processing**

- [x]  **Multi-Source Triage:** Integrated **VirusTotal API**. Two opinions are always better than one when triaging.
- [x]  **Automated Batching:** Developed the terminal "Bulk Mode" to chew through `indicators.txt` using iterative loops.
- [x]  **Rate-Limit Handling:** Implemented `time.sleep` logic. We play nice with free-tier API thresholds to avoid getting blocked.

> **Key Question:** _Can I automate the "noise reduction" process by correlating data from multiple independent sources?_

---
### **Phase 3: Telemetry Persistence & Audit Trails**

- [x]  **JSON Logging Engine:** Built a centralized JSON logging engine to capture search results, timestamps, and risk levels.
- [x]  **Persistence Engineering:** Regardless of using CLI or the GUI, the audit trail is created. No investigation goes undocumented.
- [x]  **Documentation Standards:** Finalized `README.md` and chose the **MIT License**. We're officially "Open Source" professional now.

> **Key Question:** _If an investigation happened yesterday, do I have the forensic evidence to prove what was found?_

---
### **Phase 4: Interface Design & Analyst Experience (UX)**

- [x]  **GUI Development:** Created a functional GUI using **CustomTkinter** for real-time triage.
- [x]  **Visual Signaling:** - Implemented **Red/Orange/Green** color-coding. If it's malicious, the analyst should see it before they read it. (For the sake of Ease-of-Use)
- [x]  **Functional Modularity:** Refactored the UI to include a **"File Upload"** button. No more manual typing for bulk files.

> **Key Question:** _Can I build a tool that a Tier 1 Analyst can use effectively without needing to touch the underlying code?_
---

## **Troubleshooting Summary**

|**Incident**|**Root Cause**|**Resolution**|**Analyst Insight**|
|---|---|---|---|
|**PEP 668 Error**|Linux Mint's protection of the system Python environment.|Deployed a **Python Virtual Environment (venv)** for dependency isolation.|OS stability must always come before application deployment.|
|**ModuleNotFoundError**|The OS lacked the system-level `python3-tk` bridge required for GUI rendering.|Executed `sudo apt install python3-tk` to link the venv to the display server.|Even isolated virtual environments rely on "bridge" libraries from the host OS.|
|**0% Abuse Score Mystery**|An IP (205.210.31.227) was malicious on VT but clean on AbuseIPDB.|**Logic Validation:** Confirmed that behavioral databases lag behind reputational ones.|**"Trust but Verify."** Multi-source correlation is the only way to catch "Low-and-Slow" threats.|
|**Indentation Errors**|Mixed tabs/spaces during the transition to modular functions.|Refactored the code into strict **Modular Functions** (`save_to_logs`, `process_ip`).|Clean code isn't just about style; it's about preventing scope-related logic failures.|


### Quick Reference: The Engineering "Pivots"

| **Challenge**            | **Impact**               | **Resolution**                       | **Skill Demonstrated**    |
| ------------------------ | ------------------------ | ------------------------------------ | ------------------------- |
| **Dependency Conflicts** | Prevented tool execution | Implemented `venv` isolation         | **System Administration** |
| **Missing OS Libraries** | GUI failed to render     | Bridged `python3-tk` to host OS      | **Linux Troubleshooting** |
| **Credential Exposure**  | High security risk       | Implemented `.env` secret management | **Secure Development**    |
| **Data Inconsistency**   | Fragmented audit trail   | Centralized JSON logging logic       | **Data Integrity**        |

(TL;DR summaries) 

---
## **Key Takeaways:**

- **Automation as a Filter:** Automation shouldn't replace the analyst; it should filter the noise so the analyst can focus on the "High Risk" results.
- **Logging as Evidence:** In a SOC, an investigation that isn't logged didn't happen. The shared JSON log ensures a consistent chain of evidence across different tool versions.

---

### **Possible Future Goals**

- **SIEM Connector:** Writing a script to push `triage_results.json` directly into my Splunk Home Lab for long-term trend analysis. is likely the best move to further the project. 
- **PDF Reporting:** Generating a "Formal Triage Report" that an analyst can attach directly to a ticket could be helpful.
- **Email Alerts:** Automating an "Executive Summary" email for every High-Risk IP found in bulk scans.
