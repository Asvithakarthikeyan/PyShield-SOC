
from datetime import datetime
import re


def classify_threat(event):

    signature = event.get("signature", "").lower()
    port = event.get("destination_port", 0)

    severity = "LOW"
    reason = "Normal network activity observed"

    # Rule 1: Possible port scanning
    if "port scan" in signature or "scan detected" in signature:
        severity = "HIGH"
        reason = "Possible network scanning activity"

    # Rule 2: Possible brute-force activity
    elif "brute force" in signature or "login attempts" in signature:
        severity = "CRITICAL"
        reason = "Possible repeated unauthorized login attempts"

    # Rule 3: Possible malware activity
    elif "malware" in signature or "trojan" in signature:
        severity = "CRITICAL"
        reason = "Possible malware-related activity"

    # Rule 4: Extract port from Nmap findings
    else:
        match = re.search(r"open port (\d+)", signature)

        if match:
            port = int(match.group(1))

        if port in [23, 3389, 445]:
            severity = "MEDIUM"
            reason = "Service exposure requires security review"

        elif port == 135:
            severity = "LOW"
            reason = "Windows RPC service discovered"

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": event.get("source_ip", "Unknown"),
        "destination_ip": event.get("destination_ip", "Unknown"),
        "signature": event.get("signature", "Unknown"),
        "severity": severity,
        "reason": reason
    }


if __name__ == "__main__":

    test_events = [
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "signature": "Port scan detected"
        },
        {
            "source_ip": "192.168.1.15",
            "destination_ip": "192.168.1.20",
            "signature": "Open port 445: microsoft-ds"
        },
        {
            "source_ip": "192.168.1.12",
            "destination_ip": "192.168.1.20",
            "signature": "Normal TCP traffic"
        }
    ]

    print("\n===== PYSHIELD THREAT DETECTION =====")

    for event in test_events:
        result = classify_threat(event)

        print("\nThreat Analysis:")

        for key, value in result.items():
            print(f"{key}: {value}")
