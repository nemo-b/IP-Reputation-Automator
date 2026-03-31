# 🛡️ IP-Reputation-Automator: Threat Intel Automation
**Goal:** Streamline SOC triage by consolidating reputation data from multiple threat intelligence sources into a single, actionable report.

## Project Roadmap
- [ ] **Phase 1:** Core Logic & AbuseIPDB Integration (Current)
- [ ] **Phase 2:** Bulk Processing & VirusTotal Integration
- [ ] **Phase 3:** Automated JSON Logging for Audit Trails
- [ ] **Phase 4:** GUI Development for Tier 1 Analyst Use

## Tools Used
- **Python 3.x** (Automation Core)
- **AbuseIPDB API** (IP Reputation)
- **VirusTotal API** (Malware Association)
- **Linux Mint** (Development Environment)

## Operational Value
In a high-volume SOC, manually checking 50+ IPs per shift is a waste of human capital. This tool reduces that triage time from minutes to seconds, allowing analysts to focus on actual incident response rather than data gathering.

## Setup
1. Clone the repo: `git clone https://github.com/YOUR_USER/threat-enricher-tool.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Add your API keys to a `.env` file.
