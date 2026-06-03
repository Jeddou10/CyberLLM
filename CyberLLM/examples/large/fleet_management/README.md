# fleet_management — realistic multi-module fleet backend

A mid-size FastAPI backend for managing a vehicle fleet:

- **api/** — HTTP endpoints (vehicles, drivers, OTA, telemetry, admin).
- **auth/** — login, token issuing, role-based access control.
- **telemetry/** — Kafka consumer + storage of CAN-derived telemetry.
- **ota/** — firmware staging + deployment to ECUs.
- **db/** — SQLAlchemy models and a couple of raw-SQL helpers.
- **utils/** — config loader, logging helpers.

The code is deliberately **mixed**: some modules are clean (`auth/jwt_keys.py`,
`utils/logging_setup.py`), others contain real-world-shaped vulnerabilities
across many CWE classes. The full table is in
`../../../scenarios.md`.

Layout:

```
large/fleet_management/
├── README.md
├── api/
│   ├── admin.py
│   ├── ota.py
│   ├── telemetry.py
│   └── vehicles.py
├── auth/
│   ├── jwt_keys.py
│   ├── login.py
│   └── rbac.py
├── db/
│   ├── models.py
│   └── queries.py
├── ota/
│   └── installer.py
├── telemetry/
│   └── kafka_consumer.py
└── utils/
    ├── config.py
    └── logging_setup.py
```
