"""Structured logging for ACR.

Every important pipeline stage (ingestion, detection, correlation,
reconstruction, evaluation, API errors) logs a structured record so the
pipeline can be audited. Secrets and raw payload dumps are never logged.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

_CONFIGURED = False


class JsonLikeFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        try:
            return json.dumps(payload, default=str)
        except (TypeError, ValueError):
            return str(payload)


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonLikeFormatter())
    root = logging.getLogger("acr")
    root.setLevel(level.upper())
    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(f"acr.{name}")


def log_event(logger: logging.Logger, message: str, **fields: Any) -> None:
    """Emit a structured log line without leaking sensitive payload content."""
    logger.info(message, extra={"extra_fields": fields})
