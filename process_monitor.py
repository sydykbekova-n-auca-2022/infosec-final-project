"""
Process monitor — Sensor 2 of the IDS.

Polls running processes via psutil and detects:
  - New processes (baseline diff)
  - Suspicious binaries (name blocklist)
  - Suspicious command lines (regex patterns: reverse shells, obfuscation)
  - Privilege anomalies (root processes spawned by untrusted parents)
  - Sustained resource anomalies (high CPU / memory)
With persistent logging and per-key cooldowns.
"""

import logging
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

import psutil
import yaml


CONFIG_PATH = Path(__file__).parent / "config.yaml"


# ---------- Config ----------

def load_config():
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ---------- Logging ----------

def setup_logging(alert_log_path, console_level):
    logger = logging.getLogger("ids.process")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] [proc] %(message)s",
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


# ---------- Helpers ----------

def safe_proc_info(proc):
    """Capture process info defensively — processes can die between calls."""
    try:
        with proc.oneshot():
            return {
                "pid": proc.pid,
                "ppid": proc.ppid(),
                "name": proc.name(),
                "username": proc.username(),
                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "",
                "create_time": proc.create_time(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def parent_name(ppid):
    try:
        return psutil.Process(ppid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "?"


# ---------- Detector ----------

class ProcessDetector:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger

        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in cfg.get("cmdline_patterns", [])
        ]
        self.blocklist = set(cfg.get("process_blocklist", []))
        self.trusted_root_parents = set(cfg.get("trusted_root_parents", []))

        self.known_pids = {}            # pid -> info dict
        self.last_alert = {}            # (kind, key) -> datetime

        # Sustained resource tracking: pid -> deque of (ts, cpu%, rss_mb)
        self.resource_history = defaultdict(deque)

    # --- cooldown ---

    def _can_alert(self, key, now):
        last = self.last_alert.get(key)
        if last is None:
            return True
        return (now - last).total_seconds() >= self.cfg["cooldown_seconds"]

    def _mark(self, key, now):
        self.last_alert[key] = now

    # --- detection rules ---

    def check_blocklist(self, info, now):
        if info["name"] in self.blocklist:
            key = ("blocklist", info["pid"])
            if self._can_alert(key, now):
                self.log.critical(
                    f"BLOCKLISTED BINARY: name={info['name']} pid={info['pid']} "
                    f"user={info['username']} parent={parent_name(info['ppid'])} "
                    f"cmdline={info['cmdline']!r}"
                )
                self._mark(key, now)

    def check_cmdline_patterns(self, info, now):
        cmdline = info["cmdline"]
        if not cmdline:
            return
        for pattern in self.compiled_patterns:
            if pattern.search(cmdline):
                key = ("pattern", info["pid"], pattern.pattern)
                if self._can_alert(key, now):
                    self.log.critical(
                        f"SUSPICIOUS CMDLINE: matched /{pattern.pattern}/ "
                        f"pid={info['pid']} user={info['username']} "
                        f"cmdline={cmdline!r}"
                    )
                    self._mark(key, now)
                break

    def check_root_parent(self, info, now):
        if info["username"] != "root":
            return
        parent = parent_name(info["ppid"])
        if parent in self.trusted_root_parents or parent == "?":
            return
        # Skip kernel threads (ppid 0/2)
        if info["ppid"] in (0, 2):
            return
        key = ("root_parent", info["pid"])
        if self._can_alert(key, now):
            self.log.warning(
                f"ROOT PROCESS WITH UNTRUSTED PARENT: pid={info['pid']} "
                f"name={info['name']} parent={parent}({info['ppid']}) "
                f"cmdline={info['cmdline']!r}"
            )
            self._mark(key, now)

    def check_resource_anomaly(self, proc, info, now):
        try:
            with proc.oneshot():
                cpu = proc.cpu_percent(interval=None)
                rss_mb = proc.memory_info().rss / (1024 * 1024)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return

        history = self.resource_history[info["pid"]]
        history.append((now, cpu, rss_mb))

        cutoff = now - timedelta(seconds=self.cfg["resource_window_seconds"])
        while history and history[0][0] < cutoff:
            history.popleft()

        if len(history) < 3:  # need at least 3 samples to call it "sustained"
            return

        avg_cpu = sum(h[1] for h in history) / len(history)
        avg_mem = sum(h[2] for h in history) / len(history)

        if avg_cpu >= self.cfg["cpu_threshold_percent"]:
            key = ("cpu", info["pid"])
            if self._can_alert(key, now):
                self.log.warning(
                    f"SUSTAINED HIGH CPU: pid={info['pid']} name={info['name']} "
                    f"avg={avg_cpu:.1f}% over {self.cfg['resource_window_seconds']}s "
                    f"user={info['username']} cmdline={info['cmdline']!r}"
                )
                self._mark(key, now)

        if avg_mem >= self.cfg["memory_threshold_mb"]:
            key = ("mem", info["pid"])
            if self._can_alert(key, now):
                self.log.warning(
                    f"SUSTAINED HIGH MEMORY: pid={info['pid']} name={info['name']} "
                    f"avg={avg_mem:.0f}MB over {self.cfg['resource_window_seconds']}s "
                    f"user={info['username']} cmdline={info['cmdline']!r}"
                )
                self._mark(key, now)

    # --- main snapshot loop ---

    def snapshot(self):
        now = datetime.now()
        current_pids = set()

        for proc in psutil.process_iter():
            info = safe_proc_info(proc)
            if info is None:
                continue
            pid = info["pid"]
            current_pids.add(pid)

            is_new = pid not in self.known_pids
            if is_new:
                self.known_pids[pid] = info
                self.log.info(
                    f"[NEW] pid={pid} name={info['name']} user={info['username']} "
                    f"parent={parent_name(info['ppid'])}({info['ppid']}) "
                    f"cmdline={info['cmdline']!r}"
                )
                # Run all "new process" rules
                self.check_blocklist(info, now)
                self.check_cmdline_patterns(info, now)
                self.check_root_parent(info, now)

            # Resource checks run on every snapshot for every live process
            self.check_resource_anomaly(proc, info, now)

        # Garbage-collect dead PIDs
        dead = set(self.known_pids) - current_pids
        for pid in dead:
            self.known_pids.pop(pid, None)
            self.resource_history.pop(pid, None)


# ---------- Main ----------

def main():
    cfg_full = load_config()
    cfg = cfg_full["process"]

    alert_log_path = Path(cfg_full["alert_log"])
    if not alert_log_path.is_absolute():
        alert_log_path = Path(__file__).parent / alert_log_path

    logger = setup_logging(alert_log_path, cfg_full.get("console_level", "INFO"))
    detector = ProcessDetector(cfg, logger)

    logger.info(f"Process monitor started")
    logger.info(
        f"Rules: poll {cfg['poll_seconds']}s | blocklist={len(cfg['process_blocklist'])} "
        f"items | patterns={len(cfg['cmdline_patterns'])} | "
        f"cpu>{cfg['cpu_threshold_percent']}% / mem>{cfg['memory_threshold_mb']}MB "
        f"sustained over {cfg['resource_window_seconds']}s"
    )
    logger.info(f"Alerts also written to {alert_log_path}")

    # Prime psutil's CPU% counters (first call always returns 0.0)
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # Initial snapshot establishes the baseline silently — only NEW
    # processes after this point get [NEW] events.
    initial_pids = set()
    for proc in psutil.process_iter():
        info = safe_proc_info(proc)
        if info is None:
            continue
        detector.known_pids[info["pid"]] = info
        initial_pids.add(info["pid"])
    logger.info(f"Baseline established with {len(initial_pids)} existing processes")

    while True:
        detector.snapshot()
        time.sleep(cfg["poll_seconds"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")