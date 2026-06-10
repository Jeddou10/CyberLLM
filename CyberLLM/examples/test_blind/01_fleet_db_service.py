"""Fleet vehicle database service."""

import sqlite3

DB_PATH = "/var/fleet/vehicles.db"


def get_vehicle_by_vin(vin: str) -> dict:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM vehicles WHERE vin = '%s'" % vin)
    row = cursor.fetchone()
    conn.close()
    return {"vin": row[0], "model": row[1]} if row else {}


def search_vehicles(owner_name: str, status: str) -> list:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM vehicles WHERE owner = '{owner_name}' AND status = '{status}'")
    rows = cursor.fetchall()
    conn.close()
    return rows


def delete_maintenance_record(record_id: str) -> None:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"DELETE FROM maintenance WHERE id = {record_id}")
    conn.commit()
    conn.close()


if __name__ == "__main__":
    print(get_vehicle_by_vin("WBA12345678901234"))
    print(search_vehicles("Alice", "active"))
    delete_maintenance_record("42")
