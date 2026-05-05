"""
Auth log monitor — Sensor 1 of the IDS.

Tails /var/log/auth.log for SSH events and detects:
  - Per-IP brute force (sliding window)
  - Per-user brute force (sliding window, catches distributed attacks)
  - Successful login after recent failures (possible compromise)
With sensitive-user escalation, alert cooldowns, and persistent logging.
"""

import logging
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import yaml


CONFIG_PATH = Path(__file__).parent / "config.yaml"


# ---------- Config ----------

def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ---------- Logging ----------

def setup_logging(alert_log_path, console_level):
    logger = logging.getLogger("ids.auth")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] [auth] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(getattr(logging, console_level.upper(), logging.INFO))
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.FileHandler(alert_log_path)
    fh.setLevel(logging.WARNING)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ---------- Parsing ----------

FAILED_LOGIN_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*sshd.*: "
    r"Failed password for (invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPTED_LOGIN_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2}).*sshd.*: "
    r"Accepted (password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def parse_timestamp(raw):
    return datetime.strptime(
        f"{datetime.now().year} {raw}", "%Y %b %d %H:%M:%S"
    )


def parse_line(line):
    m = FAILED_LOGIN_RE.search(line)
    if m:
        return "failed", parse_timestamp(m.group("ts")), m.group("user"), m.group("ip")
    m = ACCEPTED_LOGIN_RE.search(line)
    if m:
        return "accepted", parse_timestamp(m.group("ts")), m.group("user"), m.group("ip")
    return None


# ---------- Detector ----------

class AuthDetector:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger
        self.failures_by_ip = defaultdict(deque)
        self.failures_by_user = defaultdict(deque)
        self.last_alert = {}

    def _trim(self, window, now, seconds):
        cutoff = now - timedelta(seconds=seconds)
        while window and window[0] < cutoff:
            window.popleft()

    def _can_alert(self, key, now):
        last = self.last_alert.get(key)
        if last is None:
            return True
        return (now - last).total_seconds() >= self.cfg["cooldown_seconds"]

    def _mark(self, key, now):
        self.last_alert[key] = now

    def handle_failed(self, ts, user, ip):
        self.log.info(f"[FAIL] {ts}  user={user}  ip={ip}")

        ip_win = self.failures_by_ip[ip]
        ip_win.append(ts)
        self._trim(ip_win, ts, self.cfg["ip_window_seconds"])
        if len(ip_win) >= self.cfg["ip_threshold"]:
            key = ("ip", ip)
            if self._can_alert(key, ts):
                self.log.warning(
                    f"BRUTE-FORCE (per-IP): {len(ip_win)} failures from {ip} "
                    f"in {self.cfg['ip_window_seconds']}s (latest user={user})"
                )
                self._mark(key, ts)

        user_win = self.failures_by_user[user]
        user_win.append(ts)
        self._trim(user_win, ts, self.cfg["user_window_seconds"])
        if len(user_win) >= self.cfg["user_threshold"]:
            key = ("user", user)
            if self._can_alert(key, ts):
                level = (
                    self.log.critical
                    if user in self.cfg.get("sensitive_users", [])
                    else self.log.warning
                )
                level(
                    f"BRUTE-FORCE (per-user): {len(user_win)} failures targeting "
                    f"user={user} in {self.cfg['user_window_seconds']}s "
                    f"(latest ip={ip})"
                )
                self._mark(key, ts)

    def handle_accepted(self, ts, user, ip):
        ip_win = self.failures_by_ip.get(ip)
        recent_fails = 0
        if ip_win:
            self._trim(ip_win, ts, self.cfg["ip_window_seconds"])
            recent_fails = len(ip_win)

        if recent_fails > 0:
            self.log.critical(
                f"POSSIBLE COMPROMISE: successful login for user={user} from "
                f"ip={ip} after {recent_fails} recent failures from same IP"
            )
        else:
            self.log.info(f"[OK]   {ts}  user={user}  ip={ip}")


# ---------- Tail ----------

def tail_log(path):
    with open(path, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


# ---------- Main ----------

def main():
    cfg_full = load_config()
    cfg = cfg_full["auth"]

    alert_log_path = Path(cfg_full["alert_log"])
    if not alert_log_path.is_absolute():
        alert_log_path = Path(__file__).parent / alert_log_path

    logger = setup_logging(alert_log_path, cfg_full.get("console_level", "INFO"))
    detector = AuthDetector(cfg, logger)

    logger.info(f"Watching {cfg['log_path']}")
    logger.info(
        f"Rules: per-IP {cfg['ip_threshold']} fails / "
        f"{cfg['ip_window_seconds']}s | per-user {cfg['user_threshold']} "
        f"fails / {cfg['user_window_seconds']}s | "
        f"cooldown {cfg['cooldown_seconds']}s"
    )
    logger.info(f"Alerts also written to {alert_log_path}")

    for line in tail_log(cfg["log_path"]):
        result = parse_line(line)
        if not result:
            continue
        kind, ts, user, ip = result
        if kind == "failed":
            detector.handle_failed(ts, user, ip)
        else:
            detector.handle_accepted(ts, user, ip)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")