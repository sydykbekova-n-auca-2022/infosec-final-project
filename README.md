# infosec-final-project

# Simple Intrusion Detection System (SIDS)

A lightweight, host-based intrusion detection system written in Python for monitoring unusual activity on Linux systems. Built as a final assignment for an Information Security course.

## Overview

SIDS is a Host-based Intrusion Detection System (HIDS) that continuously monitors a Linux machine for signs of compromise or unauthorized activity. It focuses on two primary threat vectors:

- **Brute-force login detection** — monitors authentication logs for repeated failed login attempts from the same source IP within a configurable time window.
- **Process anomaly detection** — compares currently running processes against a known-good baseline snapshot and flags any new or disappeared processes.

When suspicious activity is detected, the system generates timestamped, structured alerts written to a dedicated log file.

## How It Works

```
┌──────────────────────────────────────────────────┐
│                    SIDS Engine                   │
│                                                  │
│  ┌─────────────────┐    ┌──────────────────────┐ │
│  │  Log Monitor    │    │  Process Monitor     │ │
│  │                 │    │                      │ │
│  │  Tails auth.log │    │  Snapshots running   │ │ 
│  │  Parses failures│    │  processes via `ps`  │ │
│  │  Tracks per-IP  │    │  Compares to saved   │ │
│  │  sliding window │    │  baseline.json       │ │
│  └──────┬──────────┘    └──────────┬───────────┘ │
│         │                           │            │
│         ▼                           ▼            │
│  ┌─────────────────────────────────────────────┐ │
│  │              Alert Manager                  │ │
│  │  Writes structured alerts to alerts.log     │ │
│  └─────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────┘
```

1. **Startup** — Loads configuration from `config.json` and the process baseline from `baseline.json`. Opens the system authentication log and seeks to the end (only new events are processed).
2. **Log monitoring loop** — Polls for new lines in the auth log on a configurable interval. Each line is matched against known failure patterns using regular expressions. Source IPs are extracted and tracked in a sliding time window.
3. **Threshold evaluation** — When a new failure is recorded, timestamps older than the configured window are pruned. If the remaining count for that IP exceeds the threshold, a brute-force alert is generated. A cooldown mechanism prevents duplicate alerts for the same IP.
4. **Process monitoring loop** — On a separate interval, captures a snapshot of all running processes and compares it to the baseline. New processes (not in the baseline) and disappeared processes (in the baseline but no longer running) are flagged.
5. **Alerting** — All detections are written to `alerts.log` with a standardized format including timestamp, severity, event type, and relevant metadata.

## Project Structure

```
simple-ids/
├── ids.py               # Main detection script
├── config.json          # Tunable detection thresholds and paths
├── baseline.json        # Known-good process baseline (generated)
├── alerts.log           # Alert output (created at runtime)
├── README.md            # This file
└── tests/
    └── test_ids.py      # Unit tests for detection logic
```

## Requirements

- **Operating System**: Linux (tested on Ubuntu 22.04 / 24.04)
- **Python**: 3.8 or higher
- **Privileges**: Root or sudo access (required to read `/var/log/auth.log`)
- **Dependencies**: None — uses only Python standard library modules

## Installation

Clone the repository and navigate into the project directory:

```bash
git clone https://github.com/sydykbekova-n-auca-2022/infosec-final-project.git
cd simple-ids
```

No additional packages need to be installed.

## Configuration

Edit `config.json` to customize detection behavior:

```json
{
  "auth_log_path": "/var/log/auth.log",
  "alert_log_path": "./alerts.log",
  "failed_login_threshold": 5,
  "failed_login_window_seconds": 60,
  "process_check_interval_seconds": 30,
  "log_poll_interval_seconds": 5
}
```

| Parameter                        | Description                                             | Default              |
|----------------------------------|---------------------------------------------------------|----------------------|
| `auth_log_path`                  | Path to the system authentication log                   | `/var/log/auth.log`  |
| `alert_log_path`                 | Path where alerts will be written                       | `./alerts.log`       |
| `failed_login_threshold`         | Number of failed logins before an alert fires           | `5`                  |
| `failed_login_window_seconds`    | Sliding window size in seconds for counting failures    | `60`                 |
| `process_check_interval_seconds` | How often to check for new/missing processes            | `30`                 |
| `log_poll_interval_seconds`      | How often to poll the auth log for new lines            | `5`                  |

For CentOS or RHEL systems, change `auth_log_path` to `/var/log/secure`.

## Usage

### Step 1 — Generate a Process Baseline

Run the baseline generator on a clean, known-good system state:

```bash
sudo python3 ids.py --generate-baseline
```

This captures all currently running process names and saves them to `baseline.json`. Review the file to confirm it reflects expected system state.

### Step 2 — Start Monitoring

```bash
sudo python3 ids.py
```

The script will begin tailing the authentication log and periodically checking processes. Output will appear in the terminal and alerts will be written to `alerts.log`.

### Step 3 — Review Alerts

Alerts follow this format:

```
2026-03-25 14:32:07 | WARNING | BRUTE_FORCE | IP=192.168.1.105 | Failures=6 in last 60s
2026-03-25 14:33:41 | WARNING | NEW_PROCESS | Name=ncat | PID=4821 | User=www-data
2026-03-25 14:35:12 | WARNING | MISSING_PROCESS | Name=sshd | Last seen in baseline
```

You can monitor alerts in real time from another terminal with:

```bash
tail -f alerts.log
```

## Testing

### Manual Testing

**Test brute-force detection** — Open a second terminal and attempt multiple failed SSH logins:

```bash
for i in $(seq 1 6); do
    sshpass -p 'wrongpassword' ssh testuser@localhost 2>/dev/null
done
```

Check `alerts.log` for a `BRUTE_FORCE` alert.

**Test process anomaly detection** — After generating the baseline, start an unusual process:

```bash
python3 -m http.server 9999 &
```

Wait for the next process check interval and verify a `NEW_PROCESS` alert appears.

### Unit Tests

Run the test suite to validate parsing and threshold logic:

```bash
python3 -m pytest tests/test_ids.py -v
```

## Detection Patterns

The log monitor recognizes the following authentication failure patterns:

| Pattern                            | Source                    | Example Log Entry                                                  |
|------------------------------------|---------------------------|--------------------------------------------------------------------|
| SSH password failure               | `sshd`                    | `Failed password for admin from 10.0.0.5 port 22 ssh2`             |
| PAM authentication failure         | `pam_unix`                | `authentication failure; ... rhost=10.0.0.5`                       |
| Invalid/nonexistent user attempt   | `sshd`                    | `Invalid user postgres from 10.0.0.5 port 43210`                   |

## Design Decisions

- **Sliding window** over fixed window for brute-force detection. A fixed window resets at regular intervals, which means an attacker spreading attempts across the reset boundary could evade detection. The sliding window counts failures relative to each new event, eliminating this blind spot.
- **Alert cooldown** to prevent flooding. After an IP triggers a brute-force alert, it enters a cooldown period and will not fire again until the cooldown expires. This keeps the alert log readable during an active attack.
- **Baseline comparison** rather than rule-based process allowlisting. Taking a snapshot of the real system state is more practical for a class project than maintaining a manual allowlist. The trade-off is that the baseline must be generated on a clean system.
- **Standard library only** to minimize deployment friction and external supply-chain risk.

## Known Limitations

- **Log rotation**: If the system rotates `auth.log` (e.g., via `logrotate`), the script loses its file handle. A production tool would detect inode changes and reopen the file. This could be addressed with a watchdog or by using `inotify`.
- **Evasion**: An attacker with root access could modify logs before the script reads them, or kill the IDS process itself. This is an inherent limitation of any host-based IDS without kernel-level integrity protection.
- **IPv6**: The current regex patterns only match IPv4 addresses. Extending to IPv6 would require additional patterns.
- **Baseline drift**: As the system is updated or services change, the baseline grows stale and produces false positives. A production system would support baseline refresh workflows.

## Comparison with Production Tools

| Feature                    | SIDS (This Project) | OSSEC / Wazuh         | AIDE                |
|----------------------------|---------------------|-----------------------|---------------------|
| Failed login detection     | Yes                 | Yes                   | No                  |
| Process monitoring         | Yes                 | Yes                   | No                  |
| File integrity monitoring  | No                  | Yes                   | Yes                 |
| Rootkit detection          | No                  | Yes                   | No                  |
| Centralized management     | No                  | Yes (manager/agent)   | No                  |
| Real-time log analysis     | Yes                 | Yes                   | No (scheduled)      |
| Alerting                   | File-based          | Email, Slack, SIEM    | Email, file-based   |


## License

This project is submitted as academic coursework and is provided for educational purposes only.