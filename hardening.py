def hardening_recommendations(risk):
    recommendations = []

    total = risk.get("total_risk_score", 0)
    level = risk.get("risk_level", "UNKNOWN")
    scores = risk.get("scores", {})
    reasons = risk.get("reasons", [])

    # ---------------- Severity Banner ----------------
    if level == "CRITICAL":
        recommendations.append(
            "CRITICAL: System exposure is dangerously high. Immediate remediation required."
        )
    elif level == "HIGH":
        recommendations.append(
            "HIGH RISK: Multiple attack surfaces detected. Prioritize hardening actions."
        )

    # ---------------- Privilege Hardening ----------------
    if scores.get("privilege", 0) > 0:
        recommendations.append(
            "Avoid running daily workloads as administrator/root. Use least-privilege accounts."
        )
        recommendations.append(
            "Enable privilege escalation auditing (sudo logs / Windows Event Logs)."
        )

    # ---------------- Network / Ports ----------------
    if scores.get("ports", 0) >= 10:
        recommendations.append(
            "Audit all listening ports and disable services that are not strictly required."
        )
        recommendations.append(
            "Bind exposed services to localhost where remote access is unnecessary."
        )
        recommendations.append(
            "Use host-based firewall rules to restrict port access."
        )

    # ---------------- Startup Persistence ----------------
    if scores.get("startup", 0) > 0:
        recommendations.append(
            "Review startup entries and remove unnecessary auto-start applications."
        )
        recommendations.append(
            "Restrict write permissions on startup directories to administrators only."
        )

    # ---------------- Background Services ----------------
    if scores.get("services", 0) > 0:
        recommendations.append(
            "Disable unused background services to reduce attack surface."
        )
        recommendations.append(
            "Harden service permissions and avoid running services as privileged users."
        )

    #------------------🧠 Process Risk (NEW)----------------
    if scores.get("processes", 0) > 0:
        recommendations.append(
            "Review all your Processes and disable unnecessary applications."
        )

    # ---------------- Firewall ----------------
    if scores.get("firewall", 0) > 0:
        recommendations.append(
            "Install and enable a host-based firewall (UFW, Windows Defender Firewall, PF)."
        )
        recommendations.append(
            "Adopt a default-deny inbound policy and allow only required services."
        )

    # ---------------- Bluetooth ----------------
    if scores.get("bluetooth", 0) > 0:
        recommendations.append(
            "Disable Bluetooth when not actively in use."
        )
        recommendations.append(
            "Ensure Bluetooth is set to non-discoverable mode."
        )

    # ---------------- Hygiene ----------------
    if total >= 25:
        recommendations.append(
            "Keep the operating system and all installed software fully updated."
        )
        recommendations.append(
            "Enable automatic security updates where supported."
        )

    if total >= 50:
        recommendations.append(
            "Enable centralized logging and review logs regularly."
        )
        recommendations.append(
            "Consider deploying endpoint protection or EDR tooling."
        )

    # ---------------- Clean Fallback ----------------
    if not recommendations:
        recommendations.append(
            "System posture appears healthy. Maintain updates, monitoring, and periodic audits."
        )

    return recommendations