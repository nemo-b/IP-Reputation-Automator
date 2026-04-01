import customtkinter as ctk
from enricher import ThreatEnricher
from tkinter import filedialog
import json
import os
import time

# Set professional "SOC Dark" theme (Who uses light mode????)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class SOCDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("IP-Reputation-Automator | Analyst Dashboard")
        self.geometry("850x700")
        
        # Initialize our Backend Engine
        self.enricher = ThreatEnricher()

        # --- UI ELEMENTS ---
        self.header = ctk.CTkLabel(self, text="🛡️  Threat Intelligence Triage", font=("Roboto", 28, "bold"))
        self.header.pack(pady=20)

        # Risk Indicator Label
        self.status_label = ctk.CTkLabel(self, text="STATUS: READY", font=("Roboto", 16), text_color="gray")
        self.status_label.pack(pady=5)

        # Input Frame
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(pady=10, padx=20, fill="x")

        self.ip_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter IP (e.g., 8.8.8.8)", width=350)
        self.ip_entry.pack(side="left", padx=10, pady=10)

        self.analyze_btn = ctk.CTkButton(self.input_frame, text="Run Analysis", command=self.process_ip)
        self.analyze_btn.pack(side="left", padx=5)

        # NEW: Bulk Triage Button
        self.bulk_btn = ctk.CTkButton(self.input_frame, text="Bulk Triage (File)", 
                                      command=self.bulk_triage, fg_color="transparent", border_width=2)
        self.bulk_btn.pack(side="left", padx=5)

        # Result Display (The "Report" Area)
        self.result_display = ctk.CTkTextbox(self, width=800, height=400, font=("Courier New", 14))
        self.result_display.pack(pady=20, padx=20)
        self.result_display.insert("0.0", "System Ready...\nWaiting for Analyst input.")

    def save_to_logs(self, ip, score, risk, vt, isp):
        """Helper to ensure every GUI search is logged for the audit trail."""
        log_file = "logs/triage_results.json"
        new_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": ip,
            "score": score,
            "risk": risk,
            "vt_detections": vt,
            "isp": isp
        }
        
        data = []
        if os.path.exists(log_file):
            with open(log_file, "r") as f:
                try:
                    data = json.load(f)
                except:
                    data = []
        
        data.append(new_entry)
        with open(log_file, "w") as f:
            json.dump(data, f, indent=4)

    def process_ip(self):
        """Handles single IP lookups from the entry box."""
        target_ip = self.ip_entry.get().strip()
        if not target_ip:
            return

        self.result_display.delete("0.0", "end")
        self.result_display.insert("end", f"[*] Querying Threat Intelligence for: {target_ip}...\n")
        self.update()

        # Call the Logic from enricher.py
        abuse = self.enricher.check_ip_abuse(target_ip)
        vt = self.enricher.check_vt(target_ip)
        
        score = abuse.get('abuseConfidenceScore', 0)
        risk = self.enricher.check_risk_level(score) if hasattr(self.enricher, 'check_risk_level') else self.enricher.get_risk_level(score)
        detections = vt.get('malicious', 0)
        isp = abuse.get('isp', 'Unknown Source')

        # Update Visual Status Label
        if "HIGH" in risk:
            self.status_label.configure(text=f"STATUS: {risk}", text_color="#FF4B4B")
        elif "MEDIUM" in risk:
            self.status_label.configure(text=f"STATUS: {risk}", text_color="#FFB347")
        else:
            self.status_label.configure(text=f"STATUS: {risk}", text_color="#4BB543")

        # Save to common log
        self.save_to_logs(target_ip, score, risk, detections, isp)

        report = (
            f"\n" + "="*40 + "\n"
            f" ANALYST REPORT: {target_ip}\n"
            f" " + "="*40 + "\n"
            f" [STATUS]    Risk Level: {risk}\n"
            f" [ABUSE]     Confidence Score: {score}%\n"
            f" [VIRUSTOTAL] Malicious Detections: {detections}\n"
            f" [NETWORK]   ISP: {isp}\n"
            f" " + "-"*40 + "\n"
            f" RECOMMENDED ACTION:\n"
            f" {'>>> BLOCK IMMEDIATELY' if score > 75 else '>>> MONITOR TRAFFIC' if score > 20 else '>>> NO ACTION REQUIRED'}\n"
            f" " + "="*40 + "\n"
        )
        self.result_display.insert("end", report)

    def bulk_triage(self):
        """Handles batch processing of an external .txt file."""
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if not file_path:
            return

        self.result_display.delete("0.0", "end")
        self.result_display.insert("end", f"[*] STARTING BULK TRIAGE: {os.path.basename(file_path)}\n" + "-"*50 + "\n")
        self.status_label.configure(text="STATUS: BATCH PROCESSING...", text_color="cyan")
        
        with open(file_path, "r") as f:
            for line in f:
                ip = line.strip()
                if not ip: continue
                
                self.result_display.insert("end", f"[*] Triaging {ip}...")
                self.result_display.see("end") # Auto-scroll
                self.update()
                
                abuse = self.enricher.check_ip_abuse(ip)
                vt = self.enricher.check_vt(ip)
                
                score = abuse.get('abuseConfidenceScore', 0)
                risk = self.enricher.get_risk_level(score)
                detections = vt.get('malicious', 0)
                
                self.save_to_logs(ip, score, risk, detections, abuse.get('isp', 'Unknown'))
                
                self.result_display.insert("end", f" DONE! (Risk: {risk})\n")
                time.sleep(1) # API Rate Limiting #respect

        self.result_display.insert("end", "\n[!] BULK TRIAGE COMPLETE. Audit log updated.")
        self.status_label.configure(text="STATUS: BATCH COMPLETE", text_color="#4BB543")

if __name__ == "__main__":
    app = SOCDashboard()
    app.mainloop()
