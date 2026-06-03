"""Logging configuration — fully clean (negative control)."""

from __future__ import annotations

import logging
import logging.config


def configure() -> None:
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "json": {
                    "format": (
                        "%(asctime)s level=%(levelname)s "
                        "logger=%(name)s msg=%(message)s"
                    ),
                },
            },
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "formatter": "json",
                },
            },
            "root": {
                "level": "INFO",
                "handlers": ["stdout"],
            },
        }
    )
