"""Response & mitigation layer for the Smart Packet Analyzer.

Two jobs live here, kept deliberately separate from the ML/UI code:

1. Alert generation  — actionable threats are appended to a durable JSONL
   alert log (``alerts_log.jsonl``) so they survive a browser refresh or a
   Streamlit rerun, unlike the in-session ``st.session_state.alerts`` list.

2. Mitigation        — a source IP can be *blocked* or *quarantined*. Both are
   recorded in a persisted JSON store (``response_state.json``). Blocking can
   OPTIONALLY be enforced at the operating-system firewall (Windows ``netsh``
   or Linux ``iptables``); that enforcement is off by default and only runs
   when the caller passes ``enforce=True``, because acting on an ML prediction
   at the OS level can cut off legitimate traffic on a false positive.

The module is stdlib-only so it never breaks the app's optional dependencies.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import subprocess
import time
from typing import Any, Dict, List, Tuple

# Persistence lives next to the app so it is portable across working dirs.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(_BASE_DIR, "response_state.json")
ALERT_LOG_PATH = os.path.join(_BASE_DIR, "alerts_log.jsonl")

# Tag used on OS firewall rules so we only ever remove rules we created.
_RULE_PREFIX = "SmartPacketAnalyzer_Block_"

_EMPTY_STATE: Dict[str, Any] = {"blocked": {}, "quarantined": {}}


# --------------------------------------------------------------------------- #
# Low-level persistence
# --------------------------------------------------------------------------- #
def _load_state() -> Dict[str, Any]:
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Guard against a hand-edited / truncated file.
        return {
            "blocked": dict(data.get("blocked", {})),
            "quarantined": dict(data.get("quarantined", {})),
        }
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {"blocked": {}, "quarantined": {}}


def _save_state(state: Dict[str, Any]) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, STATE_PATH)  # atomic on the same filesystem


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(str(ip))
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Alert generation (durable log)
# --------------------------------------------------------------------------- #
def record_alert(alert: Dict[str, Any]) -> None:
    """Append one actionable alert to the JSONL alert log.

    ``alert`` is expected to be the flow-info dict the app already builds; we
    strip the heavy nested ``details`` payload so the log stays compact.
    """
    entry = {k: v for k, v in alert.items() if k != "details"}
    entry.setdefault("logged_at", time.strftime("%Y-%m-%d %H:%M:%S"))
    try:
        with open(ALERT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
    except OSError:
        # Logging must never crash a live capture loop.
        pass


def record_alerts(alerts: List[Dict[str, Any]]) -> int:
    """Bulk-append alerts; returns how many were written."""
    written = 0
    for alert in alerts:
        record_alert(alert)
        written += 1
    return written


def load_alerts(limit: int = 200) -> List[Dict[str, Any]]:
    """Return the most recent ``limit`` alerts, newest last."""
    if not os.path.exists(ALERT_LOG_PATH):
        return []
    try:
        with open(ALERT_LOG_PATH, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def clear_alert_log() -> None:
    try:
        os.remove(ALERT_LOG_PATH)
    except FileNotFoundError:
        pass


# --------------------------------------------------------------------------- #
# OS-level firewall enforcement (opt-in only)
# --------------------------------------------------------------------------- #
def firewall_backend() -> str:
    """Name of the firewall tool available on this host, or 'none'."""
    system = platform.system()
    if system == "Windows" and shutil.which("netsh"):
        return "netsh"
    if system == "Linux" and shutil.which("iptables"):
        return "iptables"
    return "none"


def _run(cmd: List[str]) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"command failed: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "non-zero exit").strip()
    return True, (proc.stdout or "ok").strip()


def _os_block(ip: str) -> Tuple[bool, str]:
    """Insert an inbound+outbound drop rule for ``ip``. Requires privileges."""
    backend = firewall_backend()
    rule = _RULE_PREFIX + ip.replace(":", "_")
    if backend == "netsh":
        ok_in, msg_in = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}_in", "dir=in", "action=block", f"remoteip={ip}",
        ])
        ok_out, msg_out = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}_out", "dir=out", "action=block", f"remoteip={ip}",
        ])
        ok = ok_in and ok_out
        return ok, ("netsh rule added" if ok else f"{msg_in} / {msg_out}")
    if backend == "iptables":
        ok_in, msg_in = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        ok_out, msg_out = _run(["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
        ok = ok_in and ok_out
        return ok, ("iptables rule added" if ok else f"{msg_in} / {msg_out}")
    return False, "no supported firewall (netsh/iptables) found on this host"


def _os_unblock(ip: str) -> Tuple[bool, str]:
    backend = firewall_backend()
    rule = _RULE_PREFIX + ip.replace(":", "_")
    if backend == "netsh":
        ok_in, _ = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule}_in",
        ])
        ok_out, _ = _run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule}_out",
        ])
        return (ok_in or ok_out), "netsh rule removed"
    if backend == "iptables":
        _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
        return True, "iptables rule removed"
    return False, "no supported firewall (netsh/iptables) found on this host"


# --------------------------------------------------------------------------- #
# Mitigation actions
# --------------------------------------------------------------------------- #
def block_ip(ip: str, reason: str = "", attack_type: str = "",
             enforce: bool = False) -> Tuple[bool, str]:
    """Add ``ip`` to the blocklist.

    Always records a logical block in the persisted state. When ``enforce`` is
    True, also attempts a real OS firewall rule; the logical record is kept
    regardless so the operator sees intent even if enforcement lacks privileges.
    """
    if not is_valid_ip(ip):
        return False, f"'{ip}' is not a valid IP address"

    state = _load_state()
    enforced_ok, enforce_msg = (False, "logical block only")
    if enforce:
        enforced_ok, enforce_msg = _os_block(ip)

    state["blocked"][ip] = {
        "reason": reason,
        "attack_type": attack_type,
        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "enforced": bool(enforced_ok),
        "enforcement_detail": enforce_msg,
    }
    # A blocked IP supersedes any quarantine hold.
    state["quarantined"].pop(ip, None)
    _save_state(state)

    if enforce and not enforced_ok:
        return True, f"Logically blocked (OS enforcement failed: {enforce_msg})"
    return True, ("Blocked and enforced at firewall" if enforced_ok
                  else "Blocked (logical)")


def unblock_ip(ip: str, enforce: bool = False) -> Tuple[bool, str]:
    state = _load_state()
    existed = state["blocked"].pop(ip, None)
    _save_state(state)
    if enforce or (existed and existed.get("enforced")):
        _os_unblock(ip)
    if existed is None:
        return False, f"{ip} was not in the blocklist"
    return True, f"{ip} unblocked"


def quarantine_ip(ip: str, reason: str = "", attack_type: str = "") -> Tuple[bool, str]:
    """Flag ``ip`` for review without dropping its traffic.

    Quarantine is a logical hold only: the flow stays visible and is marked for
    an analyst decision, but is never silently cut off. Use ``block_ip`` to drop.
    """
    if not is_valid_ip(ip):
        return False, f"'{ip}' is not a valid IP address"
    state = _load_state()
    if ip in state["blocked"]:
        return False, f"{ip} is already blocked (a stronger action than quarantine)"
    state["quarantined"][ip] = {
        "reason": reason,
        "attack_type": attack_type,
        "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    _save_state(state)
    return True, f"{ip} quarantined for review"


def release_quarantine(ip: str) -> Tuple[bool, str]:
    state = _load_state()
    existed = state["quarantined"].pop(ip, None)
    _save_state(state)
    if existed is None:
        return False, f"{ip} was not quarantined"
    return True, f"{ip} released from quarantine"


# --------------------------------------------------------------------------- #
# Read helpers for the UI
# --------------------------------------------------------------------------- #
def get_state() -> Dict[str, Any]:
    return _load_state()


def is_blocked(ip: str) -> bool:
    return ip in _load_state()["blocked"]


def is_quarantined(ip: str) -> bool:
    return ip in _load_state()["quarantined"]


def status_of(ip: str) -> str:
    state = _load_state()
    if ip in state["blocked"]:
        return "BLOCKED"
    if ip in state["quarantined"]:
        return "QUARANTINED"
    return "ALLOWED"
