"""Kafka consumer for telemetry topics.

Vulnerabilities to flag:
- CODE-005: json.loads is fine, but the downstream `eval` on the
  metric expression is a remote code execution sink.
- CODE-043: no DLQ / poison-pill handling — one malformed message
  can crash the consumer loop.
- CODE-044: no SASL / TLS configured for the Kafka client.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from kafka import KafkaConsumer

from ..utils.config import load as load_settings


log = logging.getLogger("fleet.telemetry.kafka")


def _evaluate_metric_expression(expr: str, value: float) -> Any:
    # CODE-005: `expr` arrives from the message itself. eval → RCE.
    return eval(expr, {"value": value})


def run() -> None:
    settings = load_settings()
    consumer = KafkaConsumer(
        "telemetry.raw",
        bootstrap_servers=settings.kafka_brokers,
        # CODE-044: no security_protocol / sasl_mechanism configured.
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        auto_offset_reset="latest",
    )
    for msg in consumer:
        payload = msg.value
        # CODE-043: any exception here kills the loop.
        result = _evaluate_metric_expression(
            payload.get("expr", "value"),
            float(payload["value"]),
        )
        log.info("telemetry vin=%s metric=%s result=%s",
                 payload["vin"], payload["metric"], result)
