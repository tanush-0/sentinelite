from flask import Flask, render_template, send_file, jsonify, make_response, Response
import json
import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

DATA_FILE = "data/latest.json"
HISTORY_FILE = "data/history.json"

app = Flask(__name__)

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

@app.route("/")
def index():
    latest = load_json(DATA_FILE, {})
    history = load_json(HISTORY_FILE, [])

    risk = latest.get("risk", {})
    scores = risk.get("scores", {})

    return render_template(
        "index.html",
        system=latest.get("system", {}),
        risk=risk,
        scores=scores,
        hardening=latest.get("hardening", []),
        history=history
    )

@app.route("/export/json")
def export_json() -> Response:  
    if not os.path.exists(DATA_FILE):
        return make_response(
            jsonify({"error": "No snapshot available"}),
            404
        )

    return send_file(
        DATA_FILE,
        as_attachment=True,
        download_name="sentinellite_report.json"
    )

@app.route("/export/pdf")
def export_pdf() -> Response:
    if not os.path.exists(DATA_FILE):
        return make_response(
            jsonify({"error": "No snapshot available"}),
            404
        )

    latest = load_json(DATA_FILE, {})
    system = latest.get("system", {})
    risk = latest.get("risk", {})
    hardening = latest.get("hardening", [])

    ts = system.get("timestamp", "latest").replace(":", "-")
    pdf_path = f"data/sentinellite_report_{ts}.pdf"

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "SentinelLite Endpoint Risk Report")

    c.setFont("Helvetica", 12)
    y = height - 80
    c.drawString(50, y, f"Hostname: {system.get('hostname', 'N/A')}")
    y -= 20
    c.drawString(50, y, f"User: {system.get('user', 'N/A')}")
    y -= 20
    c.drawString(50, y, f"OS: {system.get('os', 'N/A')} {system.get('os_release', '')}")
    y -= 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Risk Assessment")
    y -= 20

    level = risk.get("risk_level", "UNKNOWN")
    c.setFont("Helvetica", 12)

    if level == "LOW":
        c.setFillColorRGB(0, 0.6, 0)
    elif level == "MEDIUM":
        c.setFillColorRGB(0.85, 0.65, 0)
    else:
        c.setFillColorRGB(0.85, 0, 0)

    c.drawString(50, y, f"Risk Level: {level}")
    c.setFillColorRGB(0, 0, 0)

    y -= 20
    c.drawString(50, y, f"Total Risk Score: {risk.get('total_risk_score', 'N/A')}")
    y -= 40

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Hardening Recommendations")
    y -= 20
    c.setFont("Helvetica", 12)

    for rec in hardening:
        if y < 100:
            c.showPage()
            c.setFont("Helvetica-Bold", 16)
            c.drawString(50, height - 50, "SentinelLite Endpoint Risk Report")
            c.setFont("Helvetica", 12)
            y = height - 80
        c.drawString(60, y, f"- {rec}")
        y -= 20

    c.save()

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=os.path.basename(pdf_path)
    )

if __name__ == "__main__":
    app.run(debug=False)
