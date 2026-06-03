# Scenarios — what each example is for

Each row is a `(code, log, deployment)` triple plus the rule ids the
pipeline is *expected* to surface. Match this list against the
findings emitted by your run; the diff is your detection-rate metric.

Severity legend: 🟢 informational · 🟡 medium · 🟠 high · 🔴 critical.

---

## 1. Negative-control suite — should produce zero findings

| #   | Code                            | Log                       | Deployment                           | Expected tier |
|-----|---------------------------------|---------------------------|--------------------------------------|---------------|
| N.1 | `small/01_clean_auth.py`        | `logs/01_clean_baseline.log` | `deployments/01_clean_minimal.yaml` | `none`        |
| N.2 | `large/fleet_management/auth/jwt_keys.py` | `logs/01_clean_baseline.log` | `deployments/01_clean_minimal.yaml` | `none` |
| N.3 | `large/fleet_management/utils/logging_setup.py` | `logs/01_clean_baseline.log` | `deployments/01_clean_minimal.yaml` | `none` |

Purpose: measure false-positive rate. The decision agent should
report `recommended_tier=none` with high confidence.

---

## 2. Small / single-file scenarios

| #   | Code                              | Expected code findings (paper-1 asset)                                                                                                                                  |
|-----|-----------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| S.1 | `small/02_can_gateway.py`         | 🔴 CODE-003, 🔴 CODE-005, 🟠 CODE-001, 🟠 CODE-006, 🟡 CODE-017 (Material Resources / Privacy / Life & Bodily Health)                                                       |
| S.2 | `small/03_ota_updater.py`         | 🟠 CODE-007, 🔴 CODE-008 (firmware MD5 is critical), 🟠 CODE-001, 🟡 CODE-010, 🟠 CODE-011 TOCTOU (Life & Bodily Health)                                                  |
| S.3 | `small/04_telemetry_uploader.py`  | 🔴 CODE-003 (×2), 🟠 CODE-006, 🟡 CODE-008, 🔴 CODE-012 (Privacy and Personal Data)                                                                                       |
| S.4 | `small/05_mqtt_handler.c`         | 🟠 CODE-013 (×2), 🟠 CODE-015, 🟠 CODE-001, 🟡 CODE-014, 🟡 CODE-016, 🔴 CODE-003 (Life & Bodily Health is dominant)                                                       |

Recommended pairings: combine S.1 with `logs/03_can_injection.log`
and `deployments/03_complex_sdv.yaml` for a realistic attack story.

---

## 3. Medium multi-file projects

### 3a. `medium/ev_charging_api/` — combined expectation

Scan all four files (`app.py`, `auth.py`, `db.py`, `routes.py`)
together. Expected ids:

| Severity | Rule id   | File         |
|----------|-----------|--------------|
| 🟡       | CODE-017  | app.py        |
| 🔴       | CODE-003  | app.py, auth.py |
| 🟡       | CODE-018  | app.py        |
| 🟡       | CODE-019  | app.py        |
| 🟠       | CODE-002  | auth.py       |
| 🔴       | CODE-020  | auth.py       |
| 🟡       | CODE-021  | auth.py       |
| 🟡       | CODE-022  | auth.py       |
| 🔴       | CODE-012  | db.py (×3)    |
| 🟠       | CODE-023  | db.py         |
| 🟠       | CODE-001  | routes.py     |
| 🟠       | CODE-007  | routes.py     |
| 🟡       | CODE-025  | routes.py     |
| 🟠       | CODE-026  | routes.py     |
| 🔴       | CODE-005  | routes.py     |

Combined expected decision: `recommended_tier=hard`, confidence > 0.85.

### 3b. `medium/adas_decision/`

| Severity | Rule id   | File                                |
|----------|-----------|-------------------------------------|
| 🔴       | SAFE-001  | decision.py + actuator.py (event-chain) |
| 🟠       | SAFE-002  | perception.py                       |
| 🔴       | SAFE-003  | actuator.py                         |
| 🟡       | CODE-021  | decision.py                         |
| 🟡       | CODE-027  | decision.py                         |
| 🟡       | CODE-028  | perception.py                       |
| 🟡       | CODE-029  | actuator.py                         |
| 🟡       | CODE-016  | perception.py, actuator.py          |

Combined expected decision: `recommended_tier=hard` because
SAFE-001/003 are safety-critical → asset category **Life and Bodily
Health** (paper 2).

---

## 4. Large project — `large/fleet_management/`

Scan as a directory tree. Expected rule ids by module:

- **`api/admin.py`** — 🟠 CODE-026, 🟠 CODE-037, 🟠 CODE-001, 🟡 CODE-018.
- **`api/ota.py`** — 🟠 CODE-007, 🔴 CODE-038, 🟡 CODE-039.
- **`api/telemetry.py`** — 🟠 CODE-040, 🟡 CODE-041, 🟡 CODE-042.
- **`api/vehicles.py`** — 🟠 CODE-036, 🟡 CODE-027.
- **`auth/login.py`** — 🟠 CODE-002 (weak bcrypt cost), 🟡 CODE-022, 🟢 CODE-031, 🟡 CODE-032.
- **`auth/rbac.py`** — 🔴 CODE-033, 🟠 CODE-034.
- **`auth/jwt_keys.py`** — clean.
- **`db/queries.py`** — 🔴 CODE-012, 🟢 CODE-035.
- **`ota/installer.py`** — 🟡 CODE-010, 🔴 CODE-008 (firmware), 🟠 CODE-001, 🟡 CODE-045.
- **`telemetry/kafka_consumer.py`** — 🔴 CODE-005, 🟢 CODE-043, 🟠 CODE-044.
- **`utils/config.py`** — 🟠 CODE-030.
- **`utils/logging_setup.py`** — clean.

Combined expected decision: `recommended_tier=hard`, confidence > 0.90.

---

## 5. Log-only scenarios — pair with the clean code + clean deployment

| Log                            | Expected log findings                                | Expected tier   |
|--------------------------------|------------------------------------------------------|-----------------|
| `logs/01_clean_baseline.log`   | (none)                                               | `none`          |
| `logs/02_brute_force_ssh.log`  | 🟡 LOG-AUTH-03, 🟠 LOG-LATERAL-01 (post-success sudo), 🔴 LOG-PRIV-01 (shadow read) | `hard`          |
| `logs/03_can_injection.log`    | 🔴 LOG-CAN-02 (gateway-only ID from BodyCtrl), 🟠 LOG-NET-01 burst, 🟠 CODE-001 (curl in CAN payload!) | `hard`          |
| `logs/04_data_exfiltration.log`| 🟠 LOG-EXFIL-01 (DNS), 🟠 LOG-EXFIL-02, 🟠 CODE-026, 🟠 CODE-001 (admin /exec) | `hard`          |
| `logs/05_lateral_movement.log` | 🟠 LOG-LATERAL-01, 🟠 LOG-EXFIL-02, 🟡 CODE-026, 🔴 (rogue OTA accepted) | `hard`          |
| `logs/06_ddos_pattern.log`     | 🟠 LOG-DDOS-01                                       | `moderate`      |

---

## 6. Deployment-only scenarios

| Deployment                                | Expected topology findings                     | Tier        |
|-------------------------------------------|------------------------------------------------|-------------|
| `deployments/01_clean_minimal.yaml`       | (none)                                         | `none`      |
| `deployments/02_misconfigured_cloud.yaml` | 🟠 TOP-004, 🟠 TOP-005, 🔴 TOP-006, 🟠 TOP-002 | `hard`      |
| `deployments/03_complex_sdv.yaml`         | 🟠 TOP-001, 🟠 TOP-007, 🟠 TOP-002, 🟠 TOP-008, poison-path from `pirate_radio` → `rag_navigation` (paper 2) | `hard` |

---

## 7. End-to-end "incident" stories — recommended triples

These combine code + log + deployment so the **decision agent** has to
reason across all three inputs.

| Story                       | Code                                                 | Log                                  | Deployment                          | Expected outcome                                                                                                  |
|-----------------------------|------------------------------------------------------|--------------------------------------|-------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `bench:CAN-attack`          | `small/02_can_gateway.py`                            | `logs/03_can_injection.log`          | `deployments/03_complex_sdv.yaml`   | tier=`hard`, asset=`Life and Bodily Health`. Action should include isolating the gateway ECU.                     |
| `bench:OTA-supply-chain`    | `small/03_ota_updater.py`                            | `logs/05_lateral_movement.log`       | `deployments/02_misconfigured_cloud.yaml` | tier=`hard`, asset=`Material and Economic Resources` (firmware integrity). Action: pause OTA + revoke keys.   |
| `bench:exfil-via-api`       | `medium/ev_charging_api/routes.py`                   | `logs/04_data_exfiltration.log`      | `deployments/02_misconfigured_cloud.yaml` | tier=`hard`, asset=`Privacy and Personal Data`. Action: rotate creds + block exfil IP.                       |
| `bench:adas-tampering`      | `medium/adas_decision/perception.py`                 | `logs/03_can_injection.log`          | `deployments/03_complex_sdv.yaml`   | tier=`hard`, asset=`Life and Bodily Health`. Action: degrade ADAS to driver-only.                                 |
| `bench:fleet-full`          | `large/fleet_management/api/admin.py`                | `logs/04_data_exfiltration.log`      | `deployments/02_misconfigured_cloud.yaml` | tier=`hard`, multiple assets. Action: quarantine admin portal + audit role headers.                          |
| `bench:false-positive`      | `small/01_clean_auth.py`                             | `logs/01_clean_baseline.log`         | `deployments/01_clean_minimal.yaml` | tier=`none`, confidence > 0.85.                                                                                   |

---

## 8. How to score a run

For each story above:

1. Run the pipeline.
2. Collect the rule ids in `memory/last_run.json`'s `findings[]`.
3. Compute:
   - **Detection rate** = (matched_ids) / (expected_ids).
   - **False-positive rate** = (extra_ids) / (max(matched_ids, 1)).
   - **Tier accuracy** = does `recommended_tier` match the expected tier?
4. Track these across runs. As you swap in a real LLM, you should see
   detection rate go up.

`run_examples.py` automates steps 1–3 for the listed stories.
