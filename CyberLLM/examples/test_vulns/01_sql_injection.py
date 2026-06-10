"""Test: SQL Injection vulnerabilities.

Expected detections:
  - CODE-004: SQL injection via string concatenation (% formatting)
  - CODE-012: Raw SQL with f-string interpolation

This file simulates a simple vehicle fleet database service that
builds SQL queries unsafely from user-supplied input.
"""

import sqlite3

DB_PATH = "/var/fleet/vehicles.db"


def get_vehicle_by_vin(vin: str) -> dict:
    """CODE-004: classic SQL injection via %-formatting."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles WHERE vin = '%s'" % vin)
    row = cursor.fetchone()
    conn.close()
    return {"vin": row[0], "model": row[1]} if row else {}


def search_vehicles(owner_name: str, status: str) -> list:
    """CODE-012: SQL injection via f-string."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM vehicles WHERE owner = '{owner_name}' AND status = '{status}'")
    rows = cursor.fetchall()
    conn.close()
    return rows


def delete_maintenance_record(record_id: str) -> None:
    """CODE-012: another f-string SQL injection — DELETE is even more dangerous."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM maintenance WHERE id = {record_id}")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    # Normal usage — but attacker could supply: ' OR 1=1 --
    print(get_vehicle_by_vin("WBA12345678901234"))
    print(search_vehicles("Alice", "active"))
    delete_maintenance_record("42")
