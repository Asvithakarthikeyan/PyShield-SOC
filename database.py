
import sqlite3
import os

DB_PATH = "logs/pyshield.db"


def create_database():

    os.makedirs("logs", exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            signature TEXT,
            severity TEXT,
            reason TEXT
        )
    """)

    connection.commit()
    connection.close()

    print("PyShield database initialized successfully.")


def save_event(event):

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, source_ip, destination_ip,
         signature, severity, reason)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"],
        event["source_ip"],
        event["destination_ip"],
        event["signature"],
        event["severity"],
        event["reason"]
    ))

    connection.commit()
    connection.close()

    print("Security event saved successfully.")


def get_events():

    connection = sqlite3.connect(DB_PATH)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM security_events
        ORDER BY id DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events


if __name__ == "__main__":

    create_database()

    print("\nSaved Security Events:")

    for event in get_events():
        print(event)
