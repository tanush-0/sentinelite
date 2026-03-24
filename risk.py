SUSPICIOUS_PORTS = {21, 23, 3389, 4444, 5555}
COMMON_PORTS = {22, 80, 443, 53}

def calculate_risk(system):
    score = 0
    reasons = []

    scores = {
        "privilege": 0,
        "ports": 0,
        "startup": 0,
        "services": 0,
        "processes": 0,
        "firewall": 0,
        "bluetooth": 0
    }

    # ---------------- Privilege ----------------
    if system.get("is_admin"):
        scores["privilege"] = 15
        score += 15
        reasons.append("System is running with administrative/root privileges.")

    # ---------------- Listening Ports ----------------
    ports = system.get("listening_ports", [])
    port_score = 0
    if ports:
        for p in ports:
            if p in SUSPICIOUS_PORTS:
                port_score += 8
                reasons.append(f"{p} port is Suspicious.")
            elif p in COMMON_PORTS:
                port_score += 1
            else:
                port_score += 5
                reasons.append(f"{p} port could be harmful.")
        port_score = min(port_score, 25)
        scores["ports"] = port_score
        score += port_score
        # if len(ports) <= 3:
        #     scores["ports"] = 10
        #     score += 10
        #     reasons.append(f"{len(ports)} listening ports detected.")
        # elif len(ports) <= 10:
        #     scores["ports"] = 18
        #     score += 18
        #     reasons.append(f"Multiple listening ports detected ({len(ports)}).")
        # else:
        #     scores["ports"] = 25
        #     score += 25
        #     reasons.append(f"High network exposure: {len(ports)} listening ports.")

    # ---------------- Startup Persistence ----------------
    startup_paths = system.get("startup_paths", [])
    if startup_paths:
        scores["startup"] = min(20, len(startup_paths) * 3)
        score += scores["startup"]
        reasons.append("Startup persistence locations detected.")

    # ---------------- Background Services ----------------
    services = system.get("enabled_services", [])
    if services:
        if len(services) > 50:
            scores["services"] = 15
            score += 15
            reasons.append("Large number of enabled background services.")
        elif len(services) > 20:
            scores["services"] = 10
            score += 10
            reasons.append(f"{len(services)} number of enabled background services.")

    # -----------------🧠 Process Risk (NEW)-------------
    suspicious = system.get("suspicious_processes", [])
    if suspicious:
        scores["processes"] = min(len(suspicious) * 5, 20)
        score += scores["processes"]
        reasons.append(f"{len(suspicious)} processes are suspicious.")

    # ---------------- Firewall ----------------
    fw = system.get("firewall_status", False).lower()
    if fw in ("inactive", "disabled", "not installed", "unknown"):
        scores["firewall"] = 15
        score += 15
        reasons.append("Firewall is disabled or not properly configured.")

    # ---------------- Bluetooth ----------------
    if system.get("bluetooth_enabled"):
        scores["bluetooth"] = 10
        score += 10
        reasons.append("Bluetooth is enabled and may increase attack surface.")

    # ---------------- Risk Level ----------------
    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "total_risk_score": score,
        "risk_level": level,
        "scores": scores,
        "reasons": reasons
    }

def normalize(value: float, max_value: float) -> int:
    return min(100, int((value / max_value) * 100))