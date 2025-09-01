# threat_scorer.py

# NEW: Vulnerability definitions with descriptions and severity
VULNERABILITIES = {
    "android.permission.SEND_SMS": {
        "description": "Allows app to send SMS messages, which could incur costs or be used for fraud.",
        "severity": "High"
    },
    "android.permission.READ_SMS": {
        "description": "Allows app to read all SMS messages, potentially exposing One-Time Passwords (OTPs).",
        "severity": "High"
    },
    "android.permission.RECEIVE_SMS": {
        "description": "Allows app to intercept incoming SMS messages, a key risk for banking apps.",
        "severity": "High"
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "description": "Allows app to draw over other apps, enabling overlay attacks to steal credentials.",
        "severity": "High"
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "description": "Can read screen content and interact with other apps, a very powerful and dangerous permission.",
        "severity": "High"
    },
    "android.permission.READ_CONTACTS": {
        "description": "Allows app to read the user's contacts, a privacy risk.",
        "severity": "Medium"
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "description": "Allows app to read/write files on the device's storage.",
        "severity": "Medium"
    },
    "android.permission.CAMERA": {
        "description": "Allows app to access the camera.",
        "severity": "Medium"
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "description": "Allows app to access precise GPS location.",
        "severity": "Medium"
    }
}

def calculate_threat_score(static_results, dynamic_results):
    """Calculates a score and provides a detailed list of findings."""
    score = 0
    detailed_findings = []

    # --- Static Analysis Scoring ---
    if static_results.get("permissions"):
        for perm in static_results["permissions"]:
            if perm in VULNERABILITIES:
                vuln = VULNERABILITIES[perm]
                if vuln["severity"] == "High":
                    score += 25
                else: # Medium
                    score += 5
                detailed_findings.append({
                    "type": "Permission",
                    "finding": perm,
                    "description": vuln["description"],
                    "severity": vuln["severity"]
                })
    
    # --- Dynamic Analysis Scoring ---
    if dynamic_results.get("network_traffic"):
        score += 20
        detailed_findings.append({
            "type": "Behavior",
            "finding": "Live Network Activity",
            "description": "App was detected making network connections during runtime.",
            "severity": "Medium"
        })
    
    final_score = min(score, 100)
    return final_score, detailed_findings