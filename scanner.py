from src.threat_engine import classify_threat
import subprocess
import re
from datetime import datetime

from logs.database import create_database, save_event


def scan_network(target):
    print("\nStarting Network Scan...")
    print("Target:", target)

    try:
        command = [
            "nmap", "-sV", target
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        print("\nScan Results:")
        print(result.stdout)

        if result.returncode != 0:
            print("Scanner error:", result.stderr)
            return None

        create_database()

        for line in result.stdout.splitlines():
            match = re.match(
                r"\s*(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?",
                line
            )

            if match:
                port = match.group(1)
                service = match.group(2)
                version = match.group(3) or "Unknown"

                raw_event = {
                    "source_ip": "Nmap Scanner",
                    "destination_ip": target,
                    "destination_port": int(port),
                    "signature": f"Open port {port}: {service} {version}"
                }
                event = classify_threat(raw_event)
                save_event(event)
                print("Threat classification:", event["severity"])

        print("\nNmap findings saved to PyShield database.")
        return result.stdout

    except FileNotFoundError:
        print("Nmap is not available in PATH.")
    except subprocess.TimeoutExpired:
        print("Scan timed out.")

    return None


if __name__ == "__main__":
    target = input("Enter your own or authorized target IP: ")
    scan_network(target)
