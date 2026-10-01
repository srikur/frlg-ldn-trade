"""Read-only prerequisite checks. No key values, network scans, or radio changes."""

import importlib.util
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


KEY_NAMES = ("master_key_00", "master_key_12", "aes_kek_generation_source",
             "aes_key_generation_source")


def check_keys(path):
    try:
        text = Path(path).expanduser().read_text()
    except (OSError, UnicodeError):
        return "prod.keys is missing or unreadable. Live LDN requires your dumped Switch keys."
    keys = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        name, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value.strip()):
            return "prod.keys contains a malformed entry. Key contents are never printed."
        keys[name.strip()] = value.strip()
    missing = [name for name in KEY_NAMES if len(keys.get(name, "")) != 32]
    if missing:
        return "Missing or invalid LDN key entries: " + ", ".join(missing)
    return None


def diagnose(keys_path="~/.switch/prod.keys", phy="phy0", *, require_root=False):
    errors = []
    notes = []
    system = platform.system()
    if sys.version_info < (3, 12):
        errors.append("Live trading requires Python 3.12 or newer.")
    if system != "Linux":
        errors.append(f"The current live transport requires Linux; this host runs {system}. "
                      "Collection commands work here. Native macOS/Windows LDN is not implemented.")
    key_error = check_keys(keys_path)
    if key_error:
        errors.append(key_error)
    else:
        notes.append("Required LDN key entries are present (not a live authentication test).")
    for module in ("Crypto", "zstandard", "trio", "ldn"):
        if importlib.util.find_spec(module) is None:
            errors.append(f"Missing live dependency: {module}; install requirements.txt on Linux.")
    if system == "Linux":
        if not re.fullmatch(r"phy\d+", phy):
            errors.append("Wi-Fi radio must have a name such as phy0 or phy1.")
        else:
            radio = Path("/sys/class/ieee80211") / phy
            if not radio.exists():
                errors.append(f"{phy} is not a physical Wi-Fi radio on this host.")
            else:
                driver = radio / "device/driver"
                if driver.exists():
                    notes.append(f"{phy} driver: {driver.resolve().name}")
        for command in ("iw", "ip", "nmcli"):
            if not shutil.which(command):
                errors.append(f"Missing Linux command: {command}")
        if shutil.which("iw") and re.fullmatch(r"phy\d+", phy):
            try:
                result = subprocess.run(["iw", "phy", phy, "info"], capture_output=True,
                                        text=True, timeout=10, check=False)
                if result.returncode:
                    errors.append(f"Could not query {phy} capabilities with iw.")
                elif not re.search(r"^\s*\* monitor\s*$", result.stdout, re.M):
                    errors.append(f"{phy} does not advertise monitor mode.")
                else:
                    notes.append(f"{phy} advertises monitor mode. Frame transmission and LDN "
                                 "compatibility still require a live test.")
            except (OSError, subprocess.TimeoutExpired):
                errors.append("Wi-Fi capability query failed or timed out.")
        if os.geteuid() != 0:
            message = "The upstream Linux live backend expects root for raw Wi-Fi access."
            (errors if require_root else notes).append(message)
    notes.append("An ESP32 is optional. A compatible existing Linux Wi-Fi radio can speak LDN directly.")
    return {"platform": system, "architecture": platform.machine(),
            "errors": errors, "notes": notes}


def require_live(keys_path, phy):
    report = diagnose(keys_path, phy, require_root=True)
    if report["errors"]:
        raise RuntimeError("Live prerequisites are not met:\n- " + "\n- ".join(report["errors"]))
