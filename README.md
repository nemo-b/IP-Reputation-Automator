# 🛡️ IP-Reputation-Automator: Threat Intel Automation
**Goal:** Streamline SOC triage by consolidating reputation data from multiple threat intelligence sources into a single, actionable report.

## Project Roadmap
- [ ] **Phase 1:** Core Logic & AbuseIPDB Integration (Current)
- [ ] **Phase 2:** Bulk Processing & VirusTotal Integration
- [ ] **Phase 3:** Automated JSON Logging for Audit Trails
- [ ] **Phase 4:** GUI Development for Tier 1 Analyst Use
- [ ] **Phase 5:** SIEM Integration & Telemetry Pipeline

## Operational Value
In a high-volume SOC, manually checking 50+ IPs per shift is a waste of human capital. This tool reduces that triage time from minutes to seconds, allowing analysts to focus on actual incident response rather than data gathering.

## Setup
1. Clone the repo: `git clone https://github.com/nemo_b/threat-enricher-tool.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Add your API keys to a `.env` file.

## 📖 Usage Instructions
1. **Input:** Add suspicious IP addresses to `data/indicators.txt` (one per line).
2. **Execute:** Run the tool via the terminal:
   ```bash
   source venv/bin/activate
   python3 src/enricher.py

## Tools Used
- **Python 3.x** (Automation Core)
- **AbuseIPDB API** (IP Reputation)
- **VirusTotal API** (Malware Association)
- **Linux Mint** (Development Environment)

*Data Sources: > Sample indicators provided in data/sample_indicators.txt are sourced from the AbuseIPDB "Recent Reports" feed. These are public, real-time indicators of compromise (IoCs) used for educational triage purposes.*

## 📸 Example Visuals

<p align="center">
  <img src="images/Threat%20Triage%20CLI%20Example.png" alt="Threat Triage CLI Example" width="500">
</p>

*Example of the CLI (Command Line Interface) version.*

<p align="center">
  <img src="images/Threat%20Triage%20GUI%20Example.png" alt="Threat Triage GUI Example" width="500">
</p>

*Example of the GUI (Graphical User Interface) version.*

<p align="center">
  <img src="images/Bulk%20Triage%20Example.png" alt="Bulk Triage Example" width="500">
</p>

*Example of the "Bulk Triage" tool in the GUI version.*

<p align="center">
  <img src="images/Logging%20Example.png" alt="Logging Example" width="500">
</p>

*Example of the Logging from both versions*

<p align="center">
  <img src="images/IP%20Reputation%20Automator%20Splunk%20Results.png" alt="Splunk Integration Example" width="500">
</p>

*Example of the log results from Splunk*

<p align="center">
  <img src="images/IP%20Reputation%20Automator%20Dashboard%20Example.png" alt="Dashboard Example" width="500">
</p>

*Example of the IP-Rep Dashboard from Splunk*

### Lessons in Correlation:
During development, I observed that specific indicators (e.g., `205.210.31.227`) may return a 0% Confidence Score on AbuseIPDB while maintaining high detection rates on VirusTotal.

**Analysis:** This highlights the necessity of multi-source enrichment. An IP may not be currently engaged in "noisy" brute-force activity (tracked by AbuseIPDB) but may still serve as a "silent" malware distribution point (tracked by VirusTotal). This tool ensures analysts don't miss these "Low-and-Slow" threats.
