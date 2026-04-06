import os
import sys
import requests
import json
import time
from dotenv import load_dotenv

load_dotenv()

class ThreatEnricher:
    def __init__(self):
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not self.abuse_key or not self.vt_key:
            print("[!] ERROR: API keys missing in .env file.")
            exit(1)

    def get_risk_level(self, score):
        """Helper to translate a raw score into an actionable SOC label."""
        if score >= 75: return "🔴 High"
        if score >= 25: return "🟡 Medium"
        return "🟢 Low"

    def check_ip_abuse(self, ip_address):
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        params = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
        try:
            res = requests.get(url, headers=headers, params=params, timeout=10)
            return res.json()['data'] if res.status_code == 200 else {}
        except Exception: return {}

    def check_vt(self, ip_address):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.vt_key}
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                return res.json()['data']['attributes']['last_analysis_stats']
            return {}
        except Exception: return {}

    def save_to_logs(self, new_data, log_file="logs/triage_results.json"):
        """Appends new results to the JSON log without overwriting previous history."""
        existing_data = []
        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    existing_data = json.load(f)
            except json.JSONDecodeError:
                existing_data = []

        # If we passed a list (from bulk mode), extend. If one dict, append.
        if isinstance(new_data, list):
            existing_data.extend(new_data)
        else:
            existing_data.append(new_data)

        with open(log_file, "w") as j:
            json.dump(existing_data, j, indent=4)
        print(f"[!] Audit log updated: {log_file}")

    def process_single_ip(self, ip):
        """Logic for a single IP lookup (Used by CLI/SOAR)."""
        print(f"\n--- Triage Result: {ip} ---")
        abuse = self.check_ip_abuse(ip)
        vt = self.check_vt(ip)
        
        score = abuse.get('abuseConfidenceScore', 0)
        risk = self.get_risk_level(score)
        vt_malicious = vt.get('malicious', 0)

        print(f"[AbuseIPDB] Score: {score}% ({risk} Risk)")
        print(f"[VirusTotal] Malicious Detections: {vt_malicious}")

        return {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "score": score,
            "vt_detections": vt_malicious,
            "isp": abuse.get('isp', 'Unknown'),
            "risk_label": risk
        }

if __name__ == "__main__":
    enricher = ThreatEnricher()
    input_file = "data/indicators.txt"
    
    # --- MACHINE MODE (CLI Arguments) ---
    # Used when Splunk triggers: python3 enricher.py 1.2.3.4
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        result = enricher.process_single_ip(target_ip)
        enricher.save_to_logs(result)

    # --- HUMAN MODE (Bulk Processing) ---
    # Used when you run the script normally or have IPs in indicators.txt
    elif os.path.exists(input_file):
        bulk_results = []
        with open(input_file, "r") as f:
            for line in f:
                ip = line.strip()
                if not ip: continue
                
                result = enricher.process_single_ip(ip)
                bulk_results.append(result)
                time.sleep(1) # #respect
        
        if bulk_results:
            enricher.save_to_logs(bulk_results)
    else:
        print("[?] No IP provided and data/indicators.txt not found.")
