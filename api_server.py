#!/usr/bin/env python3
import http.server
import socketserver
import json
import urllib.request
import urllib.parse
import os
import sys
import platform
import subprocess
from datetime import datetime

PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Import configuration helper functions
def load_config():
    config_path = os.path.join(BASE_DIR, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "OLLAMA_URL": "http://localhost:11434",
        "OLLAMA_MODEL": "llama3",
        "DISCORD_WEBHOOK": "",
        "ABUSEIPDB_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "",
        "ACTIVE_RESPONSE_ENABLED": False
    }

def save_config(config_data):
    config_path = os.path.join(BASE_DIR, "config.json")
    try:
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving config: {str(e)}")
        return False

# Threat Intel Check
def query_abuseipdb(ip_address, api_key):
    if not api_key or not ip_address:
        return "AbuseIPDB Lookup: Skipped (No API Key or IP)"
        
    private_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", 
                        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]
    if any(ip_address.startswith(prefix) for prefix in private_prefixes):
         return f"AbuseIPDB Lookup: {ip_address} is a Private/Local IP. Skipping reputation check."

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("Key", api_key)
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode())
            res_data = data.get("data", {})
            score = res_data.get("abuseConfidenceScore", 0)
            country = res_data.get("countryCode", "Unknown")
            isp = res_data.get("isp", "Unknown")
            return f"AbuseIPDB Report: Confidence Score: {score}%, Country: {country}, ISP: {isp}"
    except Exception as e:
        return f"AbuseIPDB Lookup Failed: {str(e)}"

# Query Ollama
def query_ollama(url, model, prompt):
    api_url = f"{url.rstrip('/')}/api/generate"
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False
    }).encode('utf-8')
    
    req = urllib.request.Request(api_url, data=payload)
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            res_data = json.loads(response.read().decode())
            return res_data.get("response", "No response content")
    except Exception as e:
        return f"Failed to connect to Ollama at {url}. Error: {str(e)}. Make sure Ollama is running and model '{model}' is installed."

# Active Response Containment
def trigger_active_response(ip_address, is_enabled):
    if not is_enabled:
        return "Simulated: Active Response is Disabled (IP would be blocked)"
    if not ip_address:
        return "Failed: No target IP address provided"
        
    os_type = platform.system().lower()
    try:
        if os_type == "linux":
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            return f"🟢 Blocked IP {ip_address} via iptables"
        elif os_type == "windows":
            rule_name = f"Wazuh_AI_Block_{ip_address}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", 
                   f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"]
            subprocess.run(cmd, check=True)
            return f"🟢 Blocked IP {ip_address} via Windows Firewall"
        else:
            return f"⚠️ Unsupported system for auto-blocking: {os_type}"
    except Exception as e:
        return f"❌ Failed to block IP: {str(e)}"

# Discord Notification
def send_discord_webhook(webhook_url, alert_data, ai_report, action):
    if not webhook_url:
        return False
    
    rule_desc = alert_data.get("rule", {}).get("description", "Security Event Triggered")
    rule_id = alert_data.get("rule", {}).get("id", "Unknown")
    rule_level = int(alert_data.get("rule", {}).get("level", 0))
    agent_name = alert_data.get("agent", {}).get("name", "Unknown")
    
    color = 15158332 if rule_level >= 10 else 15105570 if rule_level >= 7 else 3066993  # Red, Orange, Green
    
    payload = json.dumps({
        "embeds": [{
            "title": f"🚨 AI-Triaged Security Alert: {rule_desc}",
            "color": color,
            "fields": [
                {"name": "Rule ID", "value": f"`{rule_id}` (Level {rule_level})", "inline": True},
                {"name": "Host", "value": f"`{agent_name}`", "inline": True},
                {"name": "Triggered At", "value": datetime.now().isoformat(), "inline": True},
                {"name": "🛡️ Active Response Action", "value": f"`{action}`", "inline": False},
                {"name": "🤖 SOC AI Analyst Verdict & Recommendations", "value": ai_report[:1000] + ("..." if len(ai_report) > 1000 else "")}
            ]
        }]
    }).encode('utf-8')
    
    req = urllib.request.Request(webhook_url, data=payload)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Wazuh-AI-Integrator")
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status in [200, 204]
    except Exception as e:
        print(f"Discord Webhook Failed: {str(e)}")
        return False

# Web API Request Handler
class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        # Override to serve files from the current workspace directory
        return super().translate_path(path)

    def do_POST(self):
        if self.path == "/api/config":
            self.handle_save_config()
        elif self.path == "/api/simulate":
            self.handle_simulate()
        else:
            self.send_response(404)
            self.end_headers()

    def handle_save_config(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            config_data = json.loads(post_data.decode('utf-8'))
            success = save_config(config_data)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"success": success}).encode())
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def handle_simulate(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            req_data = json.loads(post_data.decode('utf-8'))
            alert_type = req_data.get("alert_type", "1")
            
            # Retrieve current configs
            config = load_config()
            
            # Select Alert Payload
            from simulate_alert import MOCK_ALERTS
            alert = MOCK_ALERTS.get(alert_type)
            if not alert:
                raise ValueError("Invalid alert type")
                
            alert_data = alert["payload"]
            src_ip = alert_data.get("data", {}).get("srcip", "")
            
            # 1. Threat Intel Check
            threat_intel = query_abuseipdb(src_ip, config.get("ABUSEIPDB_API_KEY", ""))
            
            # 2. Query AI Triage
            rule_desc = alert_data.get("rule", {}).get("description", "No description")
            rule_id = alert_data.get("rule", {}).get("id", "Unknown")
            rule_level = alert_data.get("rule", {}).get("level", 0)
            agent_name = alert_data.get("agent", {}).get("name", "Unknown")
            full_log = alert_data.get("full_log", "No full log available")
            
            prompt = f"""
You are an L2 SOC Analyst AI Agent. Review the following security alert and threat intelligence data.

### WAZUH ALERT DETAILS
- **Rule ID**: {rule_id} (Level: {rule_level})
- **Description**: {rule_desc}
- **Affected Host**: {agent_name}
- **Raw Log**: {full_log}

### THREAT INTELLIGENCE
- {threat_intel}

### TASK
Analyze the alert and generate a concise report in Markdown format for the incident response team. 
Address the following points:
1. **Verdict**: True Positive (TP) or False Positive (FP) and why.
2. **Analysis**: Explain what the attacker attempted and its impact.
3. **Remediation**: Suggest immediate concrete actions to contain/remediate the issue.

Keep the report concise, professional, and actionable. Do not output conversational filler.
"""
            # Call Ollama
            ai_report = query_ollama(
                config.get("OLLAMA_URL", "http://localhost:11434"),
                config.get("OLLAMA_MODEL", "llama3"),
                prompt
            )
            
            # 3. Trigger Active Response
            ai_report_lower = ai_report.lower()
            is_true_positive = "true positive" in ai_report_lower or "tp" in ai_report_lower
            
            response_action = "No Action Taken"
            if is_true_positive:
                response_action = trigger_active_response(src_ip, config.get("ACTIVE_RESPONSE_ENABLED", False))
                
            # 4. Trigger Webhook Notification
            send_discord_webhook(
                config.get("DISCORD_WEBHOOK", ""),
                alert_data,
                ai_report,
                response_action
            )
            
            # Return Response
            res_payload = {
                "alert": alert_data,
                "threat_intel": threat_intel,
                "ai_report": ai_report,
                "action": response_action,
                "is_true_positive": is_true_positive
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(res_payload).encode())
            
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

def main():
    # Make sure we can import simulate_alert
    sys.path.append(BASE_DIR)
    
    # Change directory to make sure we serve files correctly
    os.chdir(BASE_DIR)
    
    handler = DashboardRequestHandler
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"==================================================")
        print(f"AI SOC Analyst Dashboard running at:")
        print(f"http://localhost:{PORT}")
        print(f"==================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            sys.exit(0)

if __name__ == "__main__":
    main()
