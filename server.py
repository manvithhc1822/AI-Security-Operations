from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pathlib import Path
from datetime import datetime
import os
import re

app = Flask(__name__)
CORS(app)

BASE_DIR = Path(__file__).resolve().parent


# ============================================================
# THREAT KEYWORDS
# ============================================================

THREAT_PATTERNS = {
    "Brute Force": [
        "failed login",
        "authentication failure",
        "invalid password",
        "too many login attempts"
    ],

    "SQL Injection": [
        "union select",
        "or 1=1",
        "drop table",
        "sql injection",
        "' or '"
    ],

    "Port Scanning": [
        "port scan",
        "nmap",
        "multiple ports",
        "scan detected"
    ],

    "Malware": [
        "malware",
        "trojan",
        "ransomware",
        "virus",
        "suspicious executable"
    ],

    "Privilege Escalation": [
        "root access",
        "admin privilege",
        "privilege escalation",
        "sudo"
    ],

    "Data Exfiltration": [
        "large data transfer",
        "data exfiltration",
        "unusual outbound",
        "sensitive data"
    ]
}


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "success",
        "message": "AI Security Operations backend is running."
    })


# ============================================================
# LOG ANALYSIS
# ============================================================

@app.route("/analyze", methods=["POST"])
def analyze_logs():

    try:

        data = request.get_json()

        if not data:
            return jsonify({
                "error": "No data received."
            }), 400

        log_text = data.get("log", "").strip()

        if not log_text:
            return jsonify({
                "error": "Please provide a security log."
            }), 400


        # ----------------------------------------------------
        # Normalize log
        # ----------------------------------------------------

        normalized_log = log_text.lower()


        # ----------------------------------------------------
        # Threat Detection
        # ----------------------------------------------------

        detected_threats = []

        for threat, patterns in THREAT_PATTERNS.items():

            for pattern in patterns:

                if pattern.lower() in normalized_log:

                    if threat not in detected_threats:
                        detected_threats.append(threat)

                    break


        # ----------------------------------------------------
        # Risk Classification
        # ----------------------------------------------------

        if len(detected_threats) >= 3:
            risk = "Critical"
            risk_score = 95

        elif len(detected_threats) == 2:
            risk = "High"
            risk_score = 80

        elif len(detected_threats) == 1:
            risk = "Medium"
            risk_score = 60

        else:
            risk = "Low"
            risk_score = 15


        # ----------------------------------------------------
        # AI-style Analysis
        # ----------------------------------------------------

        if detected_threats:

            analysis = (
                "Security indicators were detected in the supplied log. "
                "The activity should be investigated and correlated with "
                "other authentication, network and endpoint events."
            )

        else:

            analysis = (
                "No known threat pattern was detected in the supplied log. "
                "Continue monitoring the system for abnormal activity."
            )


        # ----------------------------------------------------
        # Incident Creation
        # ----------------------------------------------------

        incident_id = (
            "INC-" +
            datetime.now().strftime("%Y%m%d%H%M%S")
        )


        incident_created = len(detected_threats) > 0


        # ----------------------------------------------------
        # Investigation Assistant
        # ----------------------------------------------------

        investigation_steps = []

        if "Brute Force" in detected_threats:

            investigation_steps.extend([
                "Review failed authentication attempts.",
                "Identify the source IP address.",
                "Check whether the account was successfully accessed.",
                "Review authentication logs for related accounts."
            ])


        if "SQL Injection" in detected_threats:

            investigation_steps.extend([
                "Review web server access logs.",
                "Identify the affected application endpoint.",
                "Check database query activity.",
                "Review application input validation."
            ])


        if "Port Scanning" in detected_threats:

            investigation_steps.extend([
                "Identify the scanning source IP.",
                "Review firewall connection logs.",
                "Check destination ports.",
                "Determine whether additional hosts were scanned."
            ])


        if "Malware" in detected_threats:

            investigation_steps.extend([
                "Isolate the affected endpoint.",
                "Collect endpoint security telemetry.",
                "Check suspicious processes and files.",
                "Run an endpoint security scan."
            ])


        if "Privilege Escalation" in detected_threats:

            investigation_steps.extend([
                "Review recent privilege changes.",
                "Check administrator activity.",
                "Review sudo or privilege-management logs.",
                "Verify whether the account activity was authorized."
            ])


        if "Data Exfiltration" in detected_threats:

            investigation_steps.extend([
                "Review outbound network connections.",
                "Identify destination systems.",
                "Check transferred data volume.",
                "Investigate whether sensitive information was involved."
            ])


        if not investigation_steps:

            investigation_steps = [
                "Continue monitoring system activity.",
                "Review related logs for anomalies.",
                "Correlate the event with other security telemetry."
            ]


        # ----------------------------------------------------
        # Recommended Response
        # ----------------------------------------------------

        recommendations = []

        if risk == "Critical":

            recommendations = [
                "Create a high-priority security incident.",
                "Investigate the affected systems immediately.",
                "Review related authentication and network events.",
                "Consider isolating affected endpoints according to incident-response procedures."
            ]

        elif risk == "High":

            recommendations = [
                "Create a security incident.",
                "Investigate the source of the activity.",
                "Review related logs and endpoint telemetry.",
                "Increase monitoring for related activity."
            ]

        elif risk == "Medium":

            recommendations = [
                "Investigate the detected activity.",
                "Review related security logs.",
                "Monitor the affected system for recurrence."
            ]

        else:

            recommendations = [
                "Continue normal monitoring.",
                "Correlate the event with future security activity."
            ]


        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return jsonify({

            "status": "success",

            "pipeline": [
                "Log Collection",
                "AI Log Analysis",
                "Threat Detection",
                "Risk Classification",
                "Incident Creation",
                "AI Investigation Assistant",
                "Recommended Response",
                "Security Dashboard"
            ],

            "log_analysis": {
                "status": "completed",
                "summary": analysis
            },

            "threat_detection": {
                "detected": len(detected_threats) > 0,
                "threats": detected_threats
            },

            "risk": {
                "level": risk,
                "score": risk_score
            },

            "incident": {
                "created": incident_created,
                "incident_id": incident_id if incident_created else None
            },

            "investigation": investigation_steps,

            "recommendations": recommendations,

            "timestamp": datetime.now().isoformat()

        })


    except Exception as error:

        return jsonify({
            "status": "error",
            "error": str(error)
        }), 500


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5001))

    print("=" * 60)
    print("AI SECURITY OPERATIONS PLATFORM")
    print("=" * 60)
    print(f"http://127.0.0.1:{port}")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )