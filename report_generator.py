
import sqlite3
import csv
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "logs" / "pyshield.db"
REPORT_DIR = BASE_DIR / "reports"


def generate_report():

    REPORT_DIR.mkdir(exist_ok=True)

    if not DB_PATH.exists():
        print("Security database not found.")
        return

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp, source_ip, destination_ip,
               signature, severity, reason
        FROM security_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()

    connection.close()

    if not events:
        print("No security events available for reporting.")
        return

    filename = (
        "pyshield_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".csv"
    )

    report_path = REPORT_DIR / filename

    with open(report_path, "w", newline="", encoding="utf-8") as file:

        writer = csv.writer(file)

        writer.writerow([
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Signature",
            "Severity",
            "Reason"
        ])

        writer.writerows(events)

    print("Security report generated successfully!")
    print("Report location:", report_path)


if __name__ == "__main__":
    generate_report()
