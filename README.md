# Simple Intrusion Detection System (HIDS)

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](https://ubuntu.com/)
[![Tested on Ubuntu 24.04](https://img.shields.io/badge/tested%20on-Ubuntu%2024.04-orange.svg)](https://ubuntu.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A host-based intrusion detection system (HIDS) written in Python. Continuously monitors a Linux host for authentication abuse and suspicious process activity, writing prioritised alerts to a persistent log file.

## Academic Use & Consent

**Strictly for educational purposes** on an isolated VM. Not deployed against third-party systems. Reusers are responsible for ensuring compliance with local laws and policies.

## Table of Contents

- [Project Description](#project-description)
- [Architecture Overview](#architecture-overview)
- [Tech Stack](#tech-stack)
- [Setup & Run](#setup--run-instructions)
- [Testing with Two Machines](#testing-with-two-machines)
- [Screenshots](#screenshots--diagrams)

## Project Description

### Problem It Solves

An unmonitored Linux host is blind to:
- **Brute-force SSH attacks** — most common entry point
- **Distributed attacks** — rotating IPs to evade per-IP rate limits
- **Successful logins after failures** — strongest breach indicator
- **Suspicious processes** — reverse shells, reconnaissance tools, credential attacks
- **Privilege anomalies** — root-owned processes from untrusted parents
- **Resource anomalies** — cryptominers, runaway processes
- **Network anomalies** — outbound connections from shells to external IPs

### Solution

This HIDS:
- Monitors `/var/log/auth.log` and running processes in real time
- Uses signature, threshold, and baseline-based detection
- Writes alerts with timestamps and severity to `alerts.log`
- Fully configurable via `config.yaml` — no code changes needed

## Architecture Overview

```mermaid
flowchart TD
    CFG["config.yaml<br/>thresholds, rules"]
    AUTH["auth_monitor.py<br/>• Tails /var/log/auth.log<br/>• Per-IP brute-force<br/>• Per-user brute-force<br/>• Success after failure"]
    PROC["process_monitor.py<br/>• Blocklists<br/>• Cmdline patterns<br/>• Root-parent checks<br/>• Resource anomalies<br/>• Network connections"]
    LOG["Logger"]
    ALERT["alerts.log"]
    CONSOLE["Console"]
    
    CFG --> AUTH
    CFG --> PROC
    AUTH --> LOG
    PROC --> LOG
    LOG --> ALERT
    LOG --> CONSOLE
```

**Components:**

1. **Auth Monitor** — tails `/var/log/auth.log`, detects per-IP/per-user brute-force, escalates sensitive users to CRITICAL
2. **Process Monitor** — snapshots processes, detects blocklisted binaries, suspicious command lines, root privilege anomalies, resource anomalies, network connections
3. **Config** — single YAML file controls all thresholds and patterns
4. **Alerts** — timestamped, severity-tagged logs to `alerts.log` and console

## Tech Stack

- **Python 3.10+** (tested 3.12.3)
- **psutil** — process monitoring
- **PyYAML** — config parsing
- **Ubuntu 24.04 LTS** — test environment
- **OpenSSH + rsyslog** — auth log source

## Setup and Run Instructions

### Prerequisites
- **Python 3.10+** (tested 3.12.3)
- **Ubuntu 24.04 LTS** (or similar Linux)
- `sudo` access and `git`

### Installation (5 minutes)

```bash
# 1. Clone
git clone https://github.com/sydykbekova-n-auca-2022/infosec-final-project.git
cd infosec-final-project

# 2. Install system packages
sudo apt update
sudo apt install -y python3.12-venv openssh-server rsyslog
sudo systemctl enable --now ssh rsyslog

# 3. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Verify
python3 -c "import psutil, yaml; print('✓ Success')"
```

### Running the IDS

**Quick start (recommended):**
```bash
./run_all.sh
```
Starts both monitors and tails alerts. Press `Ctrl+C` to stop.

**Manual start (3 terminals):**

Terminal 1:
```bash
source venv/bin/activate
sudo venv/bin/python3 auth_monitor.py
```

Terminal 2:
```bash
source venv/bin/activate
python3 process_monitor.py
```

Terminal 3:
```bash
tail -f alerts.log
```

### Configuration

Edit `config.yaml` to tune detection (no code changes needed):

```yaml
auth:
  ip_threshold: 3              # Alert after N failed logins (default: 5)
  ip_window_seconds: 30        # Within N seconds (default: 60)

process:
  cpu_threshold_percent: 50    # Alert if avg CPU > N% (default: 80)
  memory_threshold_mb: 300     # Alert if avg mem > N MB (default: 500)

console_level: DEBUG           # Show DEBUG+ on console (default: INFO)
```

### Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: psutil` | `source venv/bin/activate && pip install -r requirements.txt` |
| `venv/ not found` | `python3 -m venv venv` in project directory |
| `sudo: venv/bin/python3: command not found` | Ensure you're in project directory; use full path |
| `No auth events` | `sudo systemctl restart rsyslog && ls -la /var/log/auth.log` |
| `grep: /var/log/auth.log: binary file matches` | Use `grep -a` flag instead |

## Testing with Two Machines

The IDS is designed to monitor a **victim host** and detect attacks from an **attacker machine**. This section explains the setup.

### Setup Overview

```
Attacker Machine                     Victim Machine (IDS)
│                                    │
├─ Sends failed SSH logins  ───────→ ├─ Receives SSH attempts
└─ Runs suspicious commands ───────→ ├─ Logs to auth.log
                                     └─ Generates alerts
```

### Machine 1: IDS Host (Victim)
This is where the HIDS runs:
- Install and run the IDS as described above
- Note the IP address: `hostname -I`
- Keep `./run_all.sh` running and monitoring

### Machine 2: Attacker Host
This sends attacks to the IDS host. Can be:
- Your personal computer (macOS, Linux, Windows with SSH)
- Another Ubuntu VM on the same network
- Any system with SSH client installed

### Test Scenario 1: Brute-Force Attack

**On Attacker Machine:**
```bash
# Replace 192.168.1.100 with victim's IP and user@ with victim's username. Example: nur@192.168.64.3
ssh user@192.168.1.100        # (enter wrong password 3+ times)
ssh user@192.168.1.100        # (wrong password)
ssh user@192.168.1.100        # (wrong password)
```

**Expected on Victim (IDS) machine:**
```
[WARNING] [auth] BRUTE-FORCE (per-IP): source=192.168.1.X 3 failures in 60s
```

### Test Scenario 2: Brute-Force on Sensitive User

**On Attacker Machine:**
```bash
# Replace IP with victim's IP
ssh root@192.168.1.100       # (wrong password 3+ times)
ssh root@192.168.1.100       # (wrong password)
ssh root@192.168.1.100       # (wrong password)
```

**Expected on Victim (IDS) machine:**
```
[CRITICAL] [auth] BRUTE-FORCE (per-user): user=root 3 failures in 300s
```

### Test Scenario 3: Successful Login After Failures

**On Attacker Machine:**
```bash
# Try wrong password twice, then right password
ssh nur@192.168.1.100        # (wrong)
ssh nur@192.168.1.100        # (wrong)
ssh nur@192.168.1.100        # (correct password - login succeeds)
```

**Expected on Victim (IDS) machine:**
```
[CRITICAL] [auth] POSSIBLE COMPROMISE: successful login after failures from source=192.168.1.X
```

### Test Scenario 4: Local Suspicious Process

**On Victim Machine (where IDS runs):**
```bash
# While IDS is monitoring, run one of these in another terminal:
bash -i                      # Reverse shell pattern
nc -h                        # Netcat (blocklisted)
```

**Expected alert:**
```
[CRITICAL] [proc] SUSPICIOUS CMDLINE: matched /bash\s+-i/...
[CRITICAL] [proc] BLOCKLISTED BINARY: name=nc...
```

### Viewing Results

After tests, on Victim Machine:

```bash
# View CRITICAL alerts only
grep "CRITICAL" alerts.log

# View all CRITICAL + WARNING
tail -30 alerts.log | grep -E "CRITICAL|WARNING"

# Count brute-force attempts by IP
grep "BRUTE-FORCE" alerts.log | tail -10
```

## Screenshots & Diagrams

Screenshots:`assets/` 

## Demo link



## Feedback link



## Pitch presentation



---

**Author:** Nurkyz Sydykbekova  
**Course:** Information Security - Final Project  
**Language:** Python 3.12  
**License:** Academic Use Only
