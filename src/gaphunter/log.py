"""Structured logging setup (structlog)."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure(*, verbose: bool = False, json_logs: bool = False) -> None:
    """Configure structlog once per process. Logs go to stderr so stdout stays scriptable."""
    level = logging.DEBUG if verbose else logging.INFO
    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)
