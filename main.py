import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from logs.database import create_database
from network_scanner.scanner import scan_network
from packet_analyzer.analyzer import start_capture
from reports.report_generator import generate_report


def start_pyshield():

    create_database()

    print("\n================================")
    print("          PYSHIELD SOC")
    print("================================")

    while True:

        print("\n1. Scan Network using Nmap")
        print("2. Capture Network Packets")
        print("3. Generate Security Report")
        print("4. Exit")

        choice = input("\nSelect an option: ")

        if choice == "1":
            target = input("Enter authorized target IP: ")
            scan_network(target)

        elif choice == "2":
            start_capture()

        elif choice == "3":
            generate_report()

        elif choice == "4":
            print("Closing PyShield SOC...")
            break

        else:
            print("Invalid selection. Try again.")


if __name__ == "__main__":
    start_pyshield()