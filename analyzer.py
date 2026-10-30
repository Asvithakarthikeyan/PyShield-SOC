
import subprocess

from logs.database import create_database, save_event
from src.threat_engine import classify_threat

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
INTERFACE = "4"


def start_capture():

    print("\n===== PYSHIELD LIVE PACKET MONITOR =====")
    print("Continuous packet capture started...")
    print("Press Ctrl+C to stop monitoring.\n")

    command = [
        TSHARK,
        "-l",
        "-n",
        "-i", INTERFACE,
        "-f", "ip",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-e", "udp.dstport"
    ]

    create_database()

    process = None

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        for packet in process.stdout:

            fields = packet.strip().split("\t")
            fields += [""] * (5 - len(fields))

            source = fields[0]
            destination = fields[1]
            protocol_number = fields[2]

            port_text = fields[3] or fields[4] or "0"

            try:
                destination_port = int(port_text)
            except ValueError:
                destination_port = 0

            if not source or not destination:
                continue

            protocol = {
                "1": "ICMP",
                "6": "TCP",
                "17": "UDP"
            }.get(protocol_number, "OTHER")

            raw_event = {
                "source_ip": source,
                "destination_ip": destination,
                "destination_port": destination_port,
                "signature": f"{protocol} network packet"
            }

            event = classify_threat(raw_event)
            save_event(event)

            print(
                f"[LIVE] {source} -> {destination} | "
                f"{protocol} | Port: {destination_port} | "
                f"Severity: {event['severity']}"
            )

    except KeyboardInterrupt:
        print("\nStopping live packet monitoring...")

    except FileNotFoundError:
        print("TShark executable not found.")

    except PermissionError:
        print("Permission denied. Try running VS Code as Administrator.")

    finally:
        if process is not None:
            if process.stdout:
                process.stdout.close()

            if process.poll() is None:
                process.terminate()
                process.wait()

        print("Packet monitoring stopped.")


if __name__ == "__main__":
    start_capture()
