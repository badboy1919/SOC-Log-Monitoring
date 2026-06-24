# SOC Log Monitoring Lab — Wazuh SIEM Home Lab

![Status](https://img.shields.io/badge/Status-Active-green)
![Platform](https://img.shields.io/badge/Platform-VirtualBox-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-red)
![OS](https://img.shields.io/badge/Agent-Kali%20Linux-purple)

A hands-on SOC home lab simulating real-world attack detection using Wazuh SIEM. Built to develop blue team skills in log ingestion, alert tuning, and incident analysis.

---

## Architecture

```
┌─────────────────────────────────────────┐
│           VirtualBox Environment        │
│                                         │
│  ┌──────────────┐    ┌───────────────┐  │
│  │ Wazuh Server │◄───│  Kali Linux   │  │
│  │  (Manager +  │    │  (Agent +     │  │
│  │  Dashboard)  │    │  Attack Box)  │  │
│  └──────────────┘    └───────────────┘  │
│         │                               │
│  ┌──────────────┐                       │
│  │  rsyslog /   │                       │
│  │  journald    │                       │
│  │  Pipeline    │                       │
│  └──────────────┘                       │
└─────────────────────────────────────────┘
```

---

## Lab Components

| Component | Tool | Purpose |
|-----------|------|---------|
| SIEM Manager | Wazuh 4.x | Log aggregation, alerting |
| Agent | Wazuh Agent (Kali) | Log forwarding |
| Log Pipeline | rsyslog + journald | Centralized log collection |
| Dashboard | Wazuh Dashboard (OpenSearch) | Visualization, DQL queries |
| Attack Simulation | Hydra, manual auth attempts | Trigger & validate alerts |

---

## Attack Simulations Performed

### 1. SSH Brute Force Attack
- **Tool:** Hydra
- **Target:** SSH service on agent VM
- **Goal:** Trigger authentication failure alerts
- **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.x.x
```

**Expected Alerts:**
- `authentication_failed` — multiple rapid failures
- `win_auth_failure` equivalent on Linux
- Wazuh Rule ID: 5710, 5711, 5712

### 2. Sudo Auth Abuse
- **MITRE ATT&CK:** T1548.003 — Abuse Elevation Control Mechanism
- Simulated unauthorized sudo attempts to validate privilege escalation detection

### 3. Rootcheck Anomaly Detection
- Wazuh Rootcheck scanned for trojan signatures
- Detected `/usr/bin/diff` modifications flagged as anomalous
- Analyzed false positive vs true positive behavior

---

## Log Pipeline Setup

```
Kali Agent
    │
    ▼
/var/log/auth.log  +  journald
    │
    ▼
rsyslog (forwarding rules)
    │
    ▼
Wazuh Manager (port 1514)
    │
    ▼
OpenSearch / Wazuh Dashboard
```

**rsyslog config snippet:**
```bash
# /etc/rsyslog.d/wazuh.conf
*.* [REDACTED]
```

---

## Challenges & Troubleshooting

### Log Capture Issue
- **Problem:** Agent logs not appearing in Wazuh dashboard initially
- **Root Cause:** rsyslog pipeline misconfiguration — logs not forwarding correctly to manager
- **Fix Attempted:** Verified ossec.conf agent config, restarted wazuh-agent service
- **Learning:** Understanding log pipeline flow is critical — agent → manager → indexer chain must be validated at each step

```bash
# Verify agent status
sudo systemctl status wazuh-agent

# Check agent logs
sudo tail -f /var/ossec/logs/ossec.log

# Restart pipeline
sudo systemctl restart rsyslog
sudo systemctl restart wazuh-agent
```

---

## Dashboard & Alerting

- Configured custom DQL (Dashboard Query Language) queries for SSH failure correlation
- Tuned JVM heap allocation for better dashboard performance
- Created alert views filtering by `rule.groups: authentication_failed`

---

## MITRE ATT&CK Coverage

| Technique ID | Name | Detected |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | ✅ |
| T1548.003 | Sudo Abuse | ✅ |
| T1014 | Rootkit Detection | ✅ (Rootcheck) |
| T1078 | Valid Accounts — Auth Monitoring | ✅ |

---

## Key Learnings

- End-to-end log pipeline configuration (agent → manager → indexer)
- Alert rule mapping and tuning in Wazuh
- Differentiating false positives from true positives in SIEM
- MITRE ATT&CK framework mapping to real events
- JVM/OpenSearch performance optimization

---

## Skills Demonstrated

`Wazuh SIEM` `Log Analysis` `rsyslog` `SSH Brute Force Detection` `MITRE ATT&CK` `Alert Tuning` `Incident Analysis` `Linux Administration` `Blue Team` `Threat Detection`

---

## Author

**Aayush Prajapati**
B.Tech Cybersecurity | Parul University
[LinkedIn](https://www.linkedin.com/in/aayush-prajapati-)
