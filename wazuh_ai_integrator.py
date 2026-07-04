#!/usr/bin/env python3
import sys
import os
import json
import requests
from datetime import datetime

# Logging setup
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wazuh_ai_integrator.log")

def log_message(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
    print(message)

# Load configuration (either from env variables or from config.json)
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
CONFIG = {}
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, "r") as f:
            CONFIG = json.load(f)
    except Exception as e:
        log_message(f"Error loading config.json: {str(e)}")

# Fallbacks to environment variables if config.json is not present
OLLAMA_URL = CONFIG.get("OLLAMA_URL", os.environ.get("OLLAMA_URL", "http://localhost:11434"))
OLLAMA_MODEL = CONFIG.get("OLLAMA_MODEL", os.environ.get("OLLAMA_MODEL", "llama3"))
DISCORD_WEBHOOK = CONFIG.get("DISCORD_WEBHOOK", os.environ.get("DISCORD_WEBHOOK", ""))
ABUSEIPDB_API_KEY = CONFIG.get("ABUSEIPDB_API_KEY", os.environ.get("ABUSEIPDB_API_KEY", ""))
VIRUSTOTAL_API_KEY = CONFIG.get("VIRUSTOTAL_API_KEY", os.environ.get("VIRUSTOTAL_API_KEY", ""))

def query_abuseipdb(ip_address):
    """Query AbuseIPDB for IP reputation."""
    if not ABUSEIPDB_API_KEY or not ip_address:
        return "AbuseIPDB Lookup: Skipped (No API Key or IP)"
        
    # Skip private IPs
    private_prefixes = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", 
                        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127."]
    if any(ip_address.startswith(prefix) for prefix in private_prefixes):
         return f"AbuseIPDB Lookup: {ip_address} is a Private/Local IP. Skipping reputation check."

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            return f"AbuseIPDB Report: Confidence Score: {score}%, Country: {country}, ISP: {isp}"
        else:
            return f"AbuseIPDB API Error: HTTP {response.status_code}"
    except Exception as e:
        return f"AbuseIPDB Lookup Failed: {str(e)}"

def get_ai_triage(alert_data, threat_intel):
    """Send enriched alert data to Ollama for analysis."""
    # Format the prompt
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
    
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=30)
        if response.status_code == 200:
            return response.json().get("response", "No response content from Ollama")
        else:
            return f"Error: Ollama returned status code {response.status_code}. Make sure Ollama service is running."
    except Exception as e:
        return f"Failed to connect to Ollama at {OLLAMA_URL}. Error details: {str(e)}\n(Verify Ollama is started with 'ollama serve' and the model '{OLLAMA_MODEL}' is downloaded)."

def send_notification(alert_data, ai_report):
    """Send summary and AI report to Discord Webhook."""
    if not DISCORD_WEBHOOK:
        log_message("Discord Webhook URL not configured. Printing AI report to console/logs instead.")
        return
        
    rule_desc = alert_data.get("rule", {}).get("description", "Security Event Triggered")
    rule_id = alert_data.get("rule", {}).get("id", "Unknown")
    rule_level = int(alert_data.get("rule", {}).get("level", 0))
    agent_name = alert_data.get("agent", {}).get("name", "Unknown")
    
    color = 15158332 if rule_level >= 10 else 15105570 if rule_level >= 7 else 3066993  # Red, Orange, Green
    
    embed = {
        "title": f"🚨 AI-Triaged Security Alert: {rule_desc}",
        "color": color,
        "fields": [
            {"name": "Rule ID", "value": f"`{rule_id}` (Level {rule_level})", "inline": True},
            {"name": "Host", "value": f"`{agent_name}`", "inline": True},
            {"name": "Triggered At", "value": alert_data.get("timestamp", datetime.now().isoformat()), "inline": True},
            {"name": "🤖 SOC AI Analyst Verdict & Recommendations", "value": ai_report[:1000] + ("..." if len(ai_report) > 1000 else "")}
        ]
    }
    
    payload = {"embeds": [embed]}
    try:
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=5)
        if response.status_code in [200, 204]:
            log_message("Notification sent successfully to Discord.")
        else:
            log_message(f"Failed to send notification. Discord returned status {response.status_code}")
    except Exception as e:
        log_message(f"Error sending Discord notification: {str(e)}")

def main():
    log_message("Wazuh AI Integrator script started.")
    
    if len(sys.argv) < 2:
        log_message("Error: Alert JSON file path argument is missing.")
        sys.exit(1)
        
    alert_file_path = sys.argv[1]
    
    try:
        with open(alert_file_path, "r", encoding="utf-8") as f:
            alert_data = json.load(f)
    except Exception as e:
        log_message(f"Failed to load alert file '{alert_file_path}': {str(e)}")
        sys.exit(1)
        
    # Extract source IP for enrichment if present
    src_ip = alert_data.get("data", {}).get("srcip", "")
    
    # Enrichment
    log_message(f"Enriching alert. Source IP: {src_ip if src_ip else 'None'}")
    threat_intel = query_abuseipdb(src_ip)
    log_message(f"Intel summary: {threat_intel}")
    
    # AI Triage
    log_message("Requesting AI analysis from Ollama...")
    ai_report = get_ai_triage(alert_data, threat_intel)
    log_message("AI Analysis completed.")
    
    # Alerting
    send_notification(alert_data, ai_report)
    
    # Print out AI Report to stdout so Wazuh can capture it in logs if needed
    print("\n=== AI ANALYST TRIAGE REPORT ===")
    print(ai_report)
    print("=================================\n")

if __name__ == "__main__":
    main()
