"""ForensicTrail data models.

Defines the core normalized dataclasses exchanged between parser,
timeline, detector, correlator, and reporter modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class NormalizedEvent:
    """Normalized Windows Event representation.

    All modules communicate through this standardized structure. Telemetry fields
    that are absent in raw XML are set to None and noted in `warnings`.
    """

    source_file: str
    event_id: int
    file_record_num: Optional[int] = None
    record_id: Optional[int] = None
    timestamp_utc: Optional[datetime] = None
    timestamp_original: Optional[str] = None
    provider: Optional[str] = None
    channel: Optional[str] = None
    computer: Optional[str] = None
    level: Optional[int] = None
    task: Optional[int] = None
    opcode: Optional[int] = None
    keywords: Optional[str] = None
    process_id: Optional[int] = None
    thread_id: Optional[int] = None
    user_sid: Optional[str] = None
    event_data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the normalized event to a JSON-serializable dictionary.

        Returns:
            Dictionary containing primitive types with ISO-formatted timestamps.
        """
        return {
            "source_file": self.source_file,
            "file_record_num": self.file_record_num,
            "record_id": self.record_id,
            "event_id": self.event_id,
            "timestamp_utc": (
                self.timestamp_utc.isoformat() if self.timestamp_utc else None
            ),
            "timestamp_original": self.timestamp_original,
            "provider": self.provider,
            "channel": self.channel,
            "computer": self.computer,
            "level": self.level,
            "task": self.task,
            "opcode": self.opcode,
            "keywords": self.keywords,
            "process_id": self.process_id,
            "thread_id": self.thread_id,
            "user_sid": self.user_sid,
            "event_data": self.event_data,
            "warnings": list(self.warnings),
        }


@dataclass(slots=True)
class ParseSummary:
    """Summary of EVTX parsing operations and record health metrics."""

    records_seen: int = 0
    records_parsed: int = 0
    records_failed: int = 0
    errors: list[str] = field(default_factory=list)
    file_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize parse summary to dictionary."""
        return {
            "records_seen": self.records_seen,
            "records_parsed": self.records_parsed,
            "records_failed": self.records_failed,
            "errors": list(self.errors),
            "file_error": self.file_error,
        }
