# Simple Intrusion Detection System (IDS)

A host-based intrusion detection system written in Python, developed as
coursework for an Information Security course. The IDS continuously
monitors a Linux host for signs of unauthorised access and suspicious
process activity, and writes prioritised alerts to a persistent log
file for later review.

---

## Table of Contents

1. [Academic Use & Consent Statement](#academic-use--consent-statement)
2. [Project Description](#project-description)
3. [Features](#features)
4. [How It Works](#how-it-works)
5. [Architecture](#architecture)
6. [Repository Layout](#repository-layout)
7. [Lab Environment](#lab-environment)
8. [Setup](#setup)
9. [Configuration](#configuration)
10. [Running the IDS](#running-the-ids)
11. [Manual Verification of Detections](#manual-verification-of-detections)
12. [Troubleshooting](#troubleshooting)
13. [Limitations & Future Work](#limitations--future-work)
14. [References](#references)
15. [Quick Reference](#quick-reference)

---

## Academic Use & Consent Statement

This project is academic lab work submitted for an Information Security
course. It is intended **strictly for educational purposes** within an
isolated virtual machine that the author owns and controls.

- The IDS was developed and tested only against a personal Ubuntu 24.04
  virtual machine running under UTM on the author's own computer.
- All verification activity used to validate the IDS (failed SSH
  logins, manual process launches, etc.) was performed by the author
  against the author's own VM, with full consent and authorisation.
- The IDS was **not** deployed against, tested on, or directed at any
  third-party system, network, or service.
- No real user data, credentials, or production logs were collected,
  processed, or shared.

Anyone reusing this code is responsible for ensuring their own use
remains within applicable laws and institutional policies. Running an
IDS on systems you do not own, or do not have explicit written
permission to monitor, may violate computer-misuse and privacy laws in
your jurisdiction.

---

## Project Description

A simple host-based intrusion detection system (HIDS) is a security
tool that watches a single computer for signs of compromise and
notifies an operator when something looks wrong. Unlike a network IDS
(which inspects traffic between machines), a HIDS lives on the host
itself and inspects local data sources: log files, the process table,
file integrity hashes, and so on.

This project implements a small but realistic HIDS for a Linux host.
It focuses on two of the most common indicators of an attack against
a server:

1. **Authentication abuse** — repeated failed SSH logins, a successful
   login that follows a suspicious burst of failures, attempts on
   privileged usernames such as `root`.
2. **Suspicious process activity** — appearance of known attacker
   tooling, processes running with unexpected privileges,
   reverse-shell-style command lines, sustained resource anomalies.

Findings are written through Python's `logging` framework so that the
operator can watch alerts on the console in real time and review them
later in `alerts.log`.

The project is deliberately readable rather than exhaustive: the goal
is to demonstrate the *thinking* behind intrusion detection — sliding
windows, signatures, baselines, severity, false-positive control —
rather than to compete with mature tools like OSSEC, Wazuh, or
fail2ban.

---

## Features

### Currently implemented

**`auth_monitor.py` — authentication sensor**

- Real-time tailing of `/var/log/auth.log` with no missed events
  between reads.
- Per-IP brute-force detection using a sliding time window.
- Per-user brute-force detection that catches distributed attacks
  where the attacker rotates source IPs but hammers the same username.
- Sensitive-user escalation — attempts on configured high-value
  accounts (`root`, `admin`, …) are upgraded to CRITICAL severity.
- Successful-login-after-failures detection — an `Accepted password`
  event from an IP that has recent failed attempts triggers a
  CRITICAL "possible compromise" alert. This is the highest-impact
  rule because it identifies a brute-force that may have *succeeded*.
- Alert deduplication and re-arming — a configurable cooldown
  prevents duplicate alerts on the same key, while ensuring
  long-running attacks still produce periodic notifications.

**`process_monitor.py` — process sensor**

- Process baseline and diff via `psutil.process_iter()`. Each
  newly-spawned PID is captured with its parent PID, command line,
  and user.
- Suspicious-binary blocklist — known offensive-tooling names
  (`nc`, `ncat`, `nmap`, `tcpdump`, `socat`, `chisel`, `wireshark`,
  `metasploit`, `hydra`, `hashcat`, `mimikatz`, …) trigger a
  CRITICAL alert on first sighting.
- Suspicious command-line patterns — regex matches for reverse-shell
  signatures (`bash -i`, `sh -i`, `/dev/tcp/`, `nc -e`),
  in-memory shell payloads (`python -c …socket…`,
  `perl -e …socket…`), and download-and-execute patterns
  (`curl …| sh`, `wget …| bash`, `base64 -d | sh`).
- Privilege anomaly detection — root-owned processes whose parent is
  not in a configured list of trusted system parents (`init`,
  `systemd`, `sshd`, `cron`, …) are flagged.
- Sustained resource anomaly detection — processes whose average CPU
  or RSS memory exceeds configured thresholds over a rolling time
  window are flagged (a classic cryptominer signature).

**Shared infrastructure**

- Persistent, structured alert log — every WARNING and CRITICAL alert
  is appended to `alerts.log` with a timestamp, severity, and the
  sensor that produced it (`[auth]` / `[proc]`).
- YAML-based configuration — every threshold, time window, file
  path, blocklist, and pattern lives in `config.yaml`. The IDS can
  be tuned without editing code.
- Console verbosity is independently configurable from the persisted
  alert level, so operators can watch full activity without
  cluttering the alert log.

### Planned (not implemented in this submission)

- File integrity monitoring of critical paths (`/etc/passwd`,
  `/etc/shadow`, `/etc/sudoers`, `~/.ssh/authorized_keys`).
- SQLite event store for retrospective queries.
- GeoIP / threat-intel enrichment of attacker IPs.
- Flask dashboard for live alert visualisation.
- `systemd` unit so the IDS runs as a real service.

---

## How It Works

### Detection strategies

The IDS uses three complementary detection strategies:

- **Signature-based detection.** Regular expressions and string
  blocklists match known-bad strings and behaviours, e.g. the
  `Failed password for …` pattern in auth logs, or the literal binary
  name `nc` in the process table.
- **Threshold-based detection.** Sliding-window counters track
  failures per key (IP or user) and fire when counts cross thresholds
  within a time window. This is how brute-force activity is identified
  even when each individual line looks benign.
- **Baseline diffing.** The process monitor establishes a baseline of
  existing PIDs at startup, then alerts only on processes spawned
  after that point. This makes "new process" events meaningful
  signals rather than noise about every long-running daemon.

### Auth monitor lifecycle

1. Load configuration from `config.yaml`.
2. Set up a console handler at the configured level and a file
   handler at WARNING+ writing to `alerts.log`.
3. Open `/var/log/auth.log`, seek to end-of-file, and enter a
   blocking read loop (`tail -f`-style).
4. For each new line:
   - Try the failed-login regex; if it matches, update both the
     per-IP and per-user sliding windows and check thresholds.
   - Try the accepted-login regex; if it matches and the IP has
     recent failures, escalate to a CRITICAL "possible compromise"
     alert.
5. Cooldown logic records the timestamp of every alert per key. The
   same key cannot alert again until the cooldown elapses.

### Process monitor lifecycle

1. Load configuration and set up logging.
2. Prime `psutil`'s CPU percentage counters (the first call always
   returns 0.0).
3. Take an initial silent snapshot of all running PIDs to establish
   the baseline.
4. Every `poll_seconds`:
   - Iterate processes via `psutil.process_iter()`.
   - For each PID not seen before, log `[NEW]` and run the new-process
     rules: blocklist, command-line patterns, root-parent check.
   - For every live process, update its rolling CPU/memory history
     and check for sustained-anomaly thresholds.
   - Garbage-collect dead PIDs from internal state.

### Severity model

- **INFO** — normal operational events (each parsed login,
  newly-spawned PIDs, monitor startup messages). Console only.
- **WARNING** — a confirmed brute-force pattern, sustained resource
  anomaly, or a root process with an untrusted parent. Persisted to
  `alerts.log`.
- **CRITICAL** — high-impact event: brute-force on a sensitive user,
  successful login after failures, blocklisted binary, or a
  reverse-shell-style command line. Persisted to `alerts.log`.

---

## Architecture
┌─────────────────────┐
                   │     config.yaml     │
                   │ (thresholds, paths) │
                   └──────────┬──────────┘
                              │ loaded at startup
          ┌───────────────────┴───────────────────┐
          ▼                                       ▼
 ┌──────────────────────┐              ┌──────────────────────┐
 │   auth_monitor.py    │              │ process_monitor.py   │
 │  tails auth.log      │              │  polls psutil        │
 │  brute-force / IP    │              │  blocklist           │
 │  brute-force / user  │              │  cmdline patterns    │
 │  success-after-fail  │              │  root-parent check   │
 │                      │              │  sustained CPU/mem   │
 └──────────┬───────────┘              └──────────┬───────────┘
            │                                     │
            └──────────────────┬──────────────────┘
                               ▼
                ┌────────────────────────────┐
                │   Python logging module    │
                │ ┌────────┐  ┌───────────┐  │
                │ │console │  │alerts.log │  │
                │ │INFO+   │  │WARNING+   │  │
                │ └────────┘  └───────────┘  │
                └────────────────────────────┘
                
---

## Repository Layout
infosec-final/
├── auth_monitor.py        # Sensor 1: SSH auth log monitor
├── process_monitor.py     # Sensor 2: process monitor
├── config.yaml            # Tunable rules and thresholds
├── requirements.txt       # Python dependencies
├── run_all.sh             # Convenience launcher for both sensors
├── alerts.log             # Persistent alert log (created at runtime)
├── .gitignore
├── README.md              # This file
└── venv/                  # Python virtual environment (not committed)

---

## Lab Environment

Developed and tested on:

- **Host:** macOS, UTM virtualisation
- **Guest VM:** Ubuntu 24.04 LTS (ARM64), 4 GB RAM, 2 CPU cores,
  25 GB disk
- **Python:** 3.12
- **Key libraries:** `pyyaml`, `psutil`

The IDS is intended to run inside the lab VM, not on the host.

---

## Setup

### 1. Start the lab VM

Open UTM, select the Ubuntu lab VM, click **Play**, and log in.

### 2. Find the VM's current IP

UTM's shared network can reassign IPs across reboots. Inside the VM:

```bash
hostname -I
```

Use this IP wherever the README shows `192.168.64.X`.

### 3. Install dependencies

Inside the VM, in the project folder:

```bash
cd ~/infosec-final
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Ensure auth.log is being written

Ubuntu 24.04 Desktop sometimes ships without traditional syslog. To
guarantee `/var/log/auth.log` exists:

```bash
sudo apt install -y rsyslog
sudo systemctl enable --now rsyslog
```

### 5. Ensure SSH server is running

This is needed both for remote development and for failed-login
verification:

```bash
sudo apt install -y openssh-server
sudo systemctl status ssh
```

---

## Configuration

All tunable behaviour lives in `config.yaml`, organised into shared,
`auth:`, and `process:` sections.

| Key                              | Sensor   | Purpose                                                      |
|----------------------------------|----------|--------------------------------------------------------------|
| `alert_log`                      | shared   | Path to the persistent alert log.                            |
| `console_level`                  | shared   | Console verbosity.                                           |
| `auth.log_path`                  | auth     | Auth log file to tail.                                       |
| `auth.ip_window_seconds`         | auth     | Sliding window for per-IP failure counting.                  |
| `auth.ip_threshold`              | auth     | Per-IP failures within window that trigger an alert.         |
| `auth.user_window_seconds`       | auth     | Sliding window for per-user failure counting.                |
| `auth.user_threshold`            | auth     | Per-user failures within window that trigger an alert.       |
| `auth.cooldown_seconds`          | auth     | Minimum gap between repeat alerts on the same key.           |
| `auth.sensitive_users`           | auth     | Usernames whose attempts are escalated to CRITICAL.          |
| `process.poll_seconds`           | process  | Snapshot interval.                                           |
| `process.resource_window_seconds`| process  | Window over which CPU/mem averages are computed.             |
| `process.cpu_threshold_percent`  | process  | Sustained CPU% that triggers an alert.                       |
| `process.memory_threshold_mb`    | process  | Sustained RSS (MB) that triggers an alert.                   |
| `process.process_blocklist`      | process  | Process names that always trigger an alert on first sighting.|
| `process.cmdline_patterns`       | process  | Regex patterns matched against full command line.            |
| `process.cooldown_seconds`       | process  | Minimum gap between repeat alerts on the same key.           |
| `process.trusted_root_parents`   | process  | Parents that are *not* suspicious for root-owned children.   |

---

## Running the IDS

From inside the VM, in `~/infosec-final` with the venv activated.

### Run sensors separately (recommended for development)

Three terminals.

**Terminal 1 — auth monitor:**
```bash
sudo venv/bin/python3 auth_monitor.py
```
`sudo` is required because `/var/log/auth.log` is root-readable.
The explicit `venv/bin/python3` path is used so that `sudo` runs the
virtual-environment Python (with `pyyaml` installed) rather than the
system Python.

**Terminal 2 — process monitor:**
```bash
venv/bin/python3 process_monitor.py
```

**Terminal 3 — watch alerts:**
```bash
tail -f alerts.log
```

### Run both sensors with one command

```bash
./run_all.sh
```

This launches both monitors as background jobs and tails `alerts.log`
in the foreground. Press `Ctrl+C` to stop everything cleanly.

---

## Manual Verification of Detections

The detection rules are verified by performing each action manually
**against the author's own lab VM only** and observing the resulting
alert in `alerts.log`. There is no automated attack-simulation tooling
shipped with this project — verification is intentionally a hands-on
operator activity, since each step has security implications and
should be a deliberate choice.

In all examples below, replace `192.168.64.X` with the VM's current
IP from `hostname -I`.

### Auth monitor — Test 1: per-IP brute force

From the host (macOS) terminal:

```bash
ssh nur@192.168.64.X
# enter wrong password 5+ times, then let the connection drop
```

Expected: a `WARNING` line appears in `alerts.log` once the per-IP
threshold is crossed.

### Auth monitor — Test 2: per-user brute force on a sensitive account

```bash
ssh root@192.168.64.X
# enter wrong passwords
```

Expected: a `CRITICAL` alert (because `root` is in `sensitive_users`).

### Auth monitor — Test 3: successful login after failures

Trigger several wrong-password attempts, then SSH in successfully:

```bash
ssh nur@192.168.64.X
# wrong, wrong, wrong... then the correct password
```

Expected: a `CRITICAL "POSSIBLE COMPROMISE"` alert noting the recent
failure count.

### Auth monitor — Test 4: cooldown / re-arming

Trigger one brute-force burst and observe the alert. Within the
cooldown window, additional failures should *not* produce duplicate
alerts. After the cooldown elapses, fresh failures should produce a
new alert.

### Process monitor — Test 5: blocklisted binary

In a VM terminal:

```bash
nc -h
```

Expected: a `CRITICAL BLOCKLISTED BINARY` alert for `nc`.

### Process monitor — Test 6: suspicious command line

```bash
bash -i
# then immediately type 'exit'
```

Expected: a `CRITICAL SUSPICIOUS CMDLINE` alert matching the
`bash\s+-i` pattern.

### Process monitor — Test 7: sustained CPU

```bash
yes > /dev/null &
# wait ~35 seconds (longer than resource_window_seconds)
kill %1
```

Expected: a `WARNING SUSTAINED HIGH CPU` alert.

### Process monitor — Test 8: root with untrusted parent

```bash
sudo bash -c 'sleep 60' &
```

Expected (after the next snapshot): a `WARNING ROOT PROCESS WITH
UNTRUSTED PARENT` alert, because the parent of the root `bash` is the
non-system shell that ran `sudo`.

---

## Troubleshooting

### `auth.log` does not exist

```bash
sudo apt install -y rsyslog
sudo systemctl enable --now rsyslog
```

### SSH connection refused from the host

```bash
sudo systemctl status ssh
sudo systemctl enable --now ssh
```

### Stale host key warning when reconnecting

Run on the host (not the VM):

```bash
ssh-keygen -R 192.168.64.X
```

### Cannot reach VM

```bash
ping 192.168.64.X
nc -zv 192.168.64.X 22
```

In UTM, confirm the VM's network is set to **Shared Network**.

### VM IP changed between sessions

UTM's DHCP can reassign IPs after reboot. Run `hostname -I` inside the
VM and update host-side entries (SSH config, VS Code Remote-SSH host).

### `sudo: venv/bin/python3: command not found`

You're not in the project directory. Run `cd ~/infosec-final` first.

### Permission denied reading `auth.log`

`auth_monitor.py` must be launched with `sudo`.

### Process monitor sees no new processes

The first snapshot is silent on purpose — it establishes the baseline.
Spawn a new process *after* startup completes and you'll see `[NEW]`
events in the console.

---

## Limitations & Future Work

This IDS is a learning project, not production software. Known
limitations include:

- **Host-based only.** It cannot see attacks on other hosts on the
  network.
- **Signature-based detection** is by definition blind to novel
  attacker tooling renamed or recompiled to evade the blocklist.
- **No persistence beyond a single process lifetime.** Sliding windows
  reset when the IDS restarts, so an attacker pacing attempts across
  IDS restarts is not caught. A SQLite event store would address this.
- **Auth-log timestamps lack a year.** The traditional syslog format
  omits the year; the IDS assumes the current year, which can produce
  off-by-one timestamps across year boundaries.
- **Process polling has an inherent blind spot.** Very short-lived
  processes that exit between snapshots are missed. A production IDS
  would use audit-subsystem hooks (`auditd` / eBPF) instead.
- **No GeoIP / threat-intel enrichment** of attacking IPs.
- **No alert delivery channels** beyond the console and `alerts.log`
  (no email, push, webhook, or dashboard).

Planned future improvements: file integrity monitoring of critical
paths, SQLite event store for retrospective queries, GeoIP
enrichment, AbuseIPDB threat-intel lookup, a small Flask dashboard
for live alerts, desktop and webhook notifications, and a `systemd`
unit so the IDS runs as a real service.

---

## References

- `psutil` documentation — https://psutil.readthedocs.io
- OSSEC HIDS documentation — https://www.ossec.net
- Wazuh documentation — https://documentation.wazuh.com
- *Applied Network Security Monitoring*, Chris Sanders & Jason Smith
- *How Linux Works*, Brian Ward (logging and process internals)
- Ubuntu syslog / journald documentation —
  https://ubuntu.com/server/docs
- SANS Reading Room — host-based intrusion detection white papers
  https://www.sans.org/white-papers

---

## Quick Reference

| Command                                          | Purpose                            |
|--------------------------------------------------|------------------------------------|
| `hostname -I` *(in VM)*                          | Find VM's current IP               |
| `ssh nur@192.168.64.X`                           | Connect from host                  |
| `ssh-keygen -R 192.168.64.X`                     | Clear stale host key on host       |
| `cd ~/infosec-final && source venv/bin/activate` | Enter project + venv               |
| `sudo venv/bin/python3 auth_monitor.py`          | Run the auth sensor                |
| `venv/bin/python3 process_monitor.py`            | Run the process sensor             |
| `./run_all.sh`                                   | Run both sensors at once           |
| `tail -f alerts.log`                             | Watch alerts live                  |
| `grep CRITICAL alerts.log`                       | Filter to highest-severity alerts  |
| `grep -c "BRUTE-FORCE" alerts.log`               | Count brute-force alerts so far    |

---

**Author:** *Nurkyz Sydykbekova*
**Course:** Information Security — lab project