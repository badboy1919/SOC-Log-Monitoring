# SOC Log Monitoring Lab — Wazuh SIEM & AI Analyst Integration

![Status](https://img.shields.io/badge/Status-Active-green)
![Platform](https://img.shields.io/badge/Platform-VirtualBox-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-red)
![AI](https://img.shields.io/badge/AI-Ollama-purple)

A hands-on SOC home lab simulating real-world attack detection using Wazuh SIEM, now integrated with a local **AI SOC Analyst Agent** to automate alert triage, threat intelligence enrichment, and remediation recommendations.

---

## Architecture & Data Flow

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              VirtualBox / Local Environment                            │
│                                                                                        │
│  ┌───────────────────────┐           ┌──────────────────────┐                          │
│  │   Attacker Machine    │           │      Target Host     │                          │
│  │     (Kali Linux)      │──────────>│       (Ubuntu)       │                          │
│  └───────────────────────┘           └──────────────────────┘                          │
│                                                 │                                      │
│                                                 │ (rsyslog / log forwarding)           │
│                                                 ▼                                      │
│                                      ┌──────────────────────┐                          │
│                                      │    Wazuh Manager     │                          │
│                                      └──────────────────────┘                          │
│                                                 │                                      │
│                                                 │ (Custom Webhook Integration)         │
│                                                 ▼                                      │
│                                      ┌──────────────────────┐                          │
│                                      │  wazuh_ai_integrator │                          │
│                                      └──────────────────────┘                          │
│                                         /                \                             │
│                  (Threat Intel Lookup) /                  \ (Prompt Processing)        │
│                                       ▼                    ▼                           │
│                            ┌─────────────┐              ┌──────────────┐               │
│                            │ AbuseIPDB   │              │ Local LLM    │               │
│                            │ / VirusTotal│              │ (Ollama)     │               │
│                            └─────────────┘              └──────────────┘               │
│                                                                │                       │
│                                                                │ (Enriched Triage)     │
│                                                                ▼                       │
│                                                         ┌──────────────┐               │
│                                                         │ Discord/Slack│               │
│                                                         └──────────────┘               │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Lab Components

| Component | Tool / Model | Purpose |
|---|---|---|
| **SIEM Manager** | Wazuh 4.x | Centralized log aggregation, correlation, and alerting. |
| **Defensive Agent** | Wazuh Agent | Installed on target hosts to forward system/auth logs. |
| **Log Pipeline** | rsyslog + journald | Collects, structures, and forwards logs to the SIEM. |
| **AI Analyst Agent** | Python + Ollama | Python parser script running LLM triage queries. |
| **Local LLM** | `llama3` / `mistral` | Evaluates alert context and makes containment decisions. |
| **Threat Intel** | AbuseIPDB / VirusTotal API | Enriches alert payloads with IP and file reputation scores. |
| **Messaging Channel** | Discord / Slack Webhooks | Relays the finalized AI Incident Triage report to responders. |

---

## Lab Setup & Implementation

### 1. Requirements & Prerequisites
Ensure you have the following installed on your machine:
* Python 3.x
* Access to a running Ollama service (`http://localhost:11434`)
* The required python packages:
  ```bash
  pip install -r requirements.txt
  ```

### 2. Configuration
Copy `config.json.example` to `config.json` and enter your API keys and webhook URLs:
```json
{
  "OLLAMA_URL": "http://localhost:11434",
  "OLLAMA_MODEL": "llama3",
  "DISCORD_WEBHOOK": "YOUR_DISCORD_WEBHOOK_URL",
  "ABUSEIPDB_API_KEY": "YOUR_ABUSEIPDB_API_KEY",
  "VIRUSTOTAL_API_KEY": "YOUR_VIRUSTOTAL_API_KEY"
}
```
* *Note: Local/Private IPs (e.g. `192.168.x.x`, `10.x.x.x`) are automatically skipped from the Threat Intel check to conserve API quota and avoid false misses.*

---

## Local Simulation & Validation

Before deploying the integration directly onto your Wazuh Manager instance, you can test the AI enrichment pipeline using the provided local simulator:

```bash
python simulate_alert.py
```

### Attack Scenarios Available in Simulator:
1. **SSH Brute Force Attack:** Simulates a login attack from a public malicious Tor exit-node IP (`185.220.101.5`). Queries AbuseIPDB and checks reputation.
2. **SQL Injection Attempt:** Simulates a `UNION SELECT` query pattern targeting a production Nginx server.
3. **Sudo Privilege Escalation Abuse:** Simulates an unauthorized user attempting to read the `/etc/shadow` file.

---

## Deploying on Production Wazuh Manager

Follow these steps to deploy the Python integration scripts onto your live Wazuh Manager instance:

1. **Move Script:** Copy `wazuh_ai_integrator.py` and `config.json` to `/var/ossec/integrations/` directory.
2. **Set Permissions:** Make the script executable and transfer ownership:
   ```bash
   sudo chmod 750 /var/ossec/integrations/wazuh_ai_integrator.py
   sudo chown root:wazuh /var/ossec/integrations/wazuh_ai_integrator.py
   ```
3. **Configure Wazuh Manager OSSEC:** Add the following integration configuration block inside your manager's `/var/ossec/etc/ossec.conf` file:
   ```xml
   <integration>
     <name>custom-wazuh-ai-integrator</name>
     <hook_url>http://localhost:11434</hook_url> <!-- Ollama Endpoint -->
     <level>7</level> <!-- Trigger for alerts level 7 and above -->
     <alert_format>json</alert_format>
   </integration>
   ```
4. **Restart Wazuh Manager:**
   ```bash
   sudo systemctl restart wazuh-manager
   ```

---

## Key Learnings & Skills Demonstrated

* **Incident Triage Automation:** Designing security pipelines that leverage LLMs to automatically determine alert validity (TP vs. FP).
* **Threat Intel Enrichment:** Integrating external APIs (AbuseIPDB, VirusTotal) with internal SIEM alerts.
* **Log Analysis & Decoders:** Configuring log parsers and correlation rules inside Wazuh.
* **Security Scripting & Automation:** Developing clean Python integrations to automate the work of a security analyst.

---

## Author

**Aayush Prajapati**
B.Tech Cybersecurity | Parul University
* [LinkedIn](https://www.linkedin.com/in/aayush-prajapati-)
* [HackerOne](https://hackerone.com/badboy1919)
