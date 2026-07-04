#!/usr/bin/env python3
import os
import json
import subprocess
import sys

# Directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INTEGRATOR_SCRIPT = os.path.join(BASE_DIR, "wazuh_ai_integrator.py")
TEMP_ALERT_FILE = os.path.join(BASE_DIR, "temp_mock_alert.json")

# Mock Alert Payloads
MOCK_ALERTS = {
    "1": {
        "name": "SSH Brute Force Attack (External Host)",
        "payload": {
            "timestamp": "2026-07-04T15:30:22.000+0000",
            "rule": {
                "level": 10,
                "comment": "sshd: connection closed of brute force try.",
                "id": "5712",
                "description": "sshd: brute force password guessing attack detected.",
                "groups": ["syslog", "sshd", "authentication_failures"]
            },
            "agent": {
                "id": "001",
                "name": "kali-agent",
                "ip": "192.168.1.15"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "full_log": "Jul  4 15:30:20 target-vm sshd[9182]: Failed password for root from 185.220.101.5 port 49152 ssh2",
            "decoder": {
                "name": "sshd"
            },
            "data": {
                "srcip": "185.220.101.5",
                "dstport": "22",
                "srcport": "49152"
            },
            "location": "/var/log/auth.log"
        }
    },
    "2": {
        "name": "SQL Injection Attempt on Production Web Server",
        "payload": {
            "timestamp": "2026-07-04T15:32:10.000+0000",
            "rule": {
                "level": 8,
                "comment": "Web server: SQL injection attack attempt",
                "id": "31103",
                "description": "Nginx: SQL injection attempt detected in URI query parameters.",
                "groups": ["web", "nginx", "attack", "sql_injection"]
            },
            "agent": {
                "id": "002",
                "name": "web-prod-01",
                "ip": "192.168.1.20"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "full_log": "192.168.1.102 - - [04/Jul/2026:15:32:09 +0000] \"GET /api/users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1\" 400 150 \"-\" \"Mozilla/5.0 (Kali Linux)\"",
            "decoder": {
                "name": "web-accesslog"
            },
            "data": {
                "srcip": "192.168.1.102",
                "url": "/api/users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users",
                "status": "400"
            },
            "location": "/var/log/nginx/access.log"
        }
    },
    "3": {
        "name": "Sudo Privilege Escalation Abuse",
        "payload": {
            "timestamp": "2026-07-04T15:35:01.000+0000",
            "rule": {
                "level": 9,
                "comment": "Sudo: unauthorized command execution attempt",
                "id": "5402",
                "description": "Sudo: user NOT in sudoers running privileged command.",
                "groups": ["syslog", "sudo", "privilege_escalation"]
            },
            "agent": {
                "id": "001",
                "name": "kali-agent",
                "ip": "192.168.1.15"
            },
            "manager": {
                "name": "wazuh-manager"
            },
            "full_log": "Jul  4 15:35:00 target-vm sudo[9201]: guest-user : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/guest-user ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            "decoder": {
                "name": "sudo"
            },
            "data": {
                "dstuser": "root",
                "user": "guest-user",
                "command": "/usr/bin/cat /etc/shadow"
            },
            "location": "/var/log/auth.log"
        }
    }
}

def print_menu():
    print("\n==============================================")
    print("      SOC Analyst AI Agent Simulator")
    print("==============================================")
    for key, item in MOCK_ALERTS.items():
        print(f"[{key}] {item['name']}")
    print("[Q] Quit")
    print("==============================================")

def main():
    while True:
        print_menu()
        choice = input("Select an alert to simulate: ").strip().upper()
        
        if choice == 'Q':
            print("Exiting simulator. Happy hunting!")
            break
            
        if choice in MOCK_ALERTS:
            alert = MOCK_ALERTS[choice]
            print(f"\n[+] Preparing simulation for: {alert['name']}")
            
            # Write target mock alert payload to a temporary file
            try:
                with open(TEMP_ALERT_FILE, "w", encoding="utf-8") as f:
                    json.dump(alert["payload"], f, indent=4)
                print(f"[+] Temporary alert written to {TEMP_ALERT_FILE}")
            except Exception as e:
                print(f"[-] Failed to write temp file: {str(e)}")
                continue
                
            # Run the wazuh_ai_integrator.py script
            print("[*] Launching wazuh_ai_integrator.py...")
            try:
                result = subprocess.run(
                    [sys.executable, INTEGRATOR_SCRIPT, TEMP_ALERT_FILE],
                    capture_output=False, # Print outputs directly to console
                    text=True
                )
            except Exception as e:
                print(f"[-] Execution failed: {str(e)}")
            
            # Cleanup temporary file
            if os.path.exists(TEMP_ALERT_FILE):
                try:
                    os.remove(TEMP_ALERT_FILE)
                except:
                    pass
        else:
            print("[-] Invalid choice. Please choose 1, 2, 3, or Q.")

if __name__ == "__main__":
    main()
