import json
import platform
import psutil
import socket
import os
import time
import subprocess
import getpass
from datetime import datetime, timezone
from hardening import hardening_recommendations
from risk import calculate_risk

DATA_DIR = "data"
DATA_FILE = os.path.join(DATA_DIR, "latest.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")


# ------------------ Privilege ------------------

def is_admin():
    system = platform.system()

    try:
        if system in ("Linux", "Darwin"):
            return os.geteuid() == 0

        if system == "Windows":
            result = subprocess.run(
                ["net", "session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return result.returncode == 0
    except Exception:
        pass

    return False


# ------------------ Network ------------------

def get_listening_ports():
    ports = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == psutil.CONN_LISTEN and c.laddr:
                ports.add(c.laddr.port)
    except Exception:
        pass
    return sorted(ports)


# ------------------ Startup / Persistence ------------------

def detect_startup_paths():
    system = platform.system()
    paths = []

    if system == "Linux":
        paths = [
            os.path.expanduser("~/.config/autostart"),
            "/etc/systemd/system"
        ]

    elif system == "Windows":
        paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        ]

    elif system == "Darwin":
        paths = [
            os.path.expanduser("~/Library/LaunchAgents"),
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons"
        ]

    return [p for p in paths if os.path.exists(p)]


def detect_background_services():
    system = platform.system()
    services = []

    try:
        if system == "Linux":
            output = subprocess.check_output(
                ["systemctl", "list-unit-files", "--type=service", "--state=enabled"],
                text=True
            )
            services = [l.split()[0] for l in output.splitlines() if ".service" in l]

        elif system == "Windows":
            output = subprocess.check_output(
                ["sc", "query", "state=", "all"],
                shell=True,
                text=True
            )
            services = [l for l in output.splitlines() if l.strip().startswith("SERVICE_NAME")]

        elif system == "Darwin":
            output = subprocess.check_output(["launchctl", "list"], text=True)
            services = output.splitlines()[1:]

    except Exception:
        pass

    return services


# ---------------🧠 Process Risk (NEW)--------------------

def get_suspicious_processes():
    system = platform.system()
    suspicious = []
    keywords = ["hack", "inject", "keylog", "exploit"]

    if system == "Linux":
        for proc in psutil.process_iter(['name']):
            try:
                name = proc.info['name'].lower()
                if any(k in name for k in keywords):
                    suspicious.append(name)
            except:
                continue

    return suspicious

# ------------------ Bluetooth ------------------

def bluetooth_enabled():
    system = platform.system()

    try:
        if system == "Linux":
            out = subprocess.run(
                ["systemctl", "is-enabled", "bluetooth"],
                capture_output=True,
                text=True
            )
            return out.stdout.strip() == "enabled"

        elif system == "Windows":
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "Get-Service -Name bthserv | Select-Object -ExpandProperty Status"],
                text=True
            )
            return "Running" in out

        elif system == "Darwin":
            out = subprocess.check_output(
                ["defaults", "read",
                 "/Library/Preferences/com.apple.Bluetooth",
                 "ControllerPowerState"],
                text=True
            )
            return out.strip() == "1"

    except Exception:
        return False

    return False


# ------------------ Firewall ------------------

def firewall_status():
    system = platform.system()

    try:
        if system == "Linux":
            if subprocess.run(["which", "ufw"], stdout=subprocess.DEVNULL).returncode != 0:
                return "not installed"
            out = subprocess.check_output(["ufw", "status"], text=True)
            return "active" if "Status: active" in out else "inactive"

        elif system == "Windows":
            out = subprocess.check_output(
                ["powershell", "-Command",
                 "Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled"],
                text=True
            )
            return "active" if "True" in out else "inactive"

        elif system == "Darwin":
            out = subprocess.check_output(
                ["defaults", "read",
                 "/Library/Preferences/com.apple.alf",
                 "globalstate"],
                text=True
            )
            return "active" if out.strip() != "0" else "inactive"

    except Exception:
        return "unknown"

    return "unknown"


# ------------------ Collection ------------------

def collect():
    system_info = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "is_admin": is_admin(),
        "os": platform.system(),
        "os_release": platform.release(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "uptime_hours": round((time.time() - psutil.boot_time()) / 3600, 2),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "ram_usage": psutil.virtual_memory().percent,
        "listening_ports": get_listening_ports(),
        "startup_paths": detect_startup_paths(),
        "enabled_services": detect_background_services(),
        "suspicious_processes": get_suspicious_processes(),
        "bluetooth_enabled": bluetooth_enabled(),
        "firewall_status": firewall_status(),
    }

    risk = calculate_risk(system_info)
    hardening = hardening_recommendations(risk)

    report = {
        "system": system_info,
        "risk": risk,
        "hardening": hardening
    }

    os.makedirs(DATA_DIR, exist_ok=True)

    with open(DATA_FILE, "w") as f:
        json.dump(report, f, indent=4)

    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    history = json.loads(content)
        except json.JSONDecodeError:
            history = []

    history.append({
        "timestamp": system_info["timestamp"],
        "risk_score": risk["total_risk_score"],
        "risk_level": risk["risk_level"]
    })

    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

    print("✔ System audit complete")
    print(f"✔ Risk Level: {risk['risk_level']} ({risk['total_risk_score']}/100)")


if __name__ == "__main__":
    collect()