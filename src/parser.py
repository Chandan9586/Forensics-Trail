"""ForensicTrail EVTX & XML Event Parser.

Provides pure XML normalization functions and an EVTX stream parser
backed by `python-evtx`. Ensures evidence integrity by reading original
files read-only and handling malformed/corrupted records gracefully.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
from typing import Any, Optional
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx

from src.models import NormalizedEvent, ParseSummary

logger = logging.getLogger(__name__)

# EVTX file header signature (magic bytes)
EVTX_MAGIC = b"ElfFile\x00"

# Regex pattern for 7+ decimal digits in fractional seconds
_FRACTIONAL_SECONDS_RE = re.compile(r"\.(\d{6})\d+")


def _sanitize_for_csv(val: Any) -> Any:
    """Neutralize potential CSV formula injection in spreadsheet exports."""
    if isinstance(val, str) and val.startswith(("=", "+", "-", "@")):
        return f"'{val}"
    return val


def _strip_tag_namespace(tag: str) -> str:
    """Strip XML namespace prefix from an element tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_systemtime_string(raw_time: Optional[str]) -> tuple[Optional[datetime], Optional[str]]:
    """Parse Windows SystemTime XML string into an aware UTC datetime.

    Windows timestamps often contain 7 decimal digits (100ns precision).
    Python's `datetime.fromisoformat` supports up to 6 digits (microsecond).
    This function truncates excess digits to 6 while preserving the original string.

    Args:
        raw_time: The raw SystemTime attribute value from TimeCreated element.

    Returns:
        A tuple of (parsed_utc_datetime, warning_message_if_any).
    """
    if not raw_time or not raw_time.strip():
        return None, "TimeCreated SystemTime is missing or empty"

    cleaned = raw_time.strip()
    # Truncate fractional seconds with more than 6 digits to 6 digits
    truncated = _FRACTIONAL_SECONDS_RE.sub(r".\1", cleaned)

    # Standardize UTC trailing 'Z' if present
    is_zulu = truncated.endswith("Z") or truncated.endswith("z")
    if is_zulu:
        truncated = truncated[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(truncated)
        if dt.tzinfo is None:
            # Windows SystemTime is UTC by definition
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt, None
    except ValueError as exc:
        return None, f"Failed to parse timestamp '{raw_time}': {exc}"


def _insert_event_data_field(target: dict[str, Any], key: str, value: Any) -> None:
    """Insert a field into event_data, handling duplicates with _2, _3 suffixes."""
    if key not in target:
        target[key] = value
        return

    counter = 2
    while f"{key}_{counter}" in target:
        counter += 1
    target[f"{key}_{counter}"] = value


def _extract_event_data(event_data_elem: ET.Element, target: dict[str, Any]) -> None:
    """Extract Data elements from an EventData XML element."""
    unnamed_counter = 1
    for child in event_data_elem:
        tag = _strip_tag_namespace(child.tag)
        if tag == "Data":
            name = child.attrib.get("Name")
            val = (child.text or "").strip()
            if name:
                _insert_event_data_field(target, name, val)
            else:
                key = "Data" if unnamed_counter == 1 else f"Data_{unnamed_counter}"
                unnamed_counter += 1
                _insert_event_data_field(target, key, val)
        else:
            # Other elements under EventData
            val = (child.text or "").strip()
            _insert_event_data_field(target, tag, val)


def _extract_user_data(user_data_elem: ET.Element, target: dict[str, Any]) -> None:
    """Extract fields from a UserData XML element (e.g. Event 1102)."""
    for child in user_data_elem:
        # Child is typically a wrapper like <LogFileCleared>
        if len(child) > 0:
            for subchild in child:
                sub_tag = _strip_tag_namespace(subchild.tag)
                sub_val = (subchild.text or "").strip()
                _insert_event_data_field(target, sub_tag, sub_val)
        else:
            tag = _strip_tag_namespace(child.tag)
            val = (child.text or "").strip()
            _insert_event_data_field(target, tag, val)


def normalize_event_xml(
    xml_str: str,
    source_file: str,
    file_record_num: Optional[int] = None,
) -> NormalizedEvent:
    """Normalize a single Windows Event XML string into a NormalizedEvent dataclass.

    This function is pure, stateless, and fully testable without an EVTX file.
    Missing fields are populated with None and appended to `warnings`.

    Args:
        xml_str: Raw XML string of the event record.
        source_file: Name or path of the originating file.
        file_record_num: Sequential record index from the EVTX chunk/file.

    Returns:
        A populated NormalizedEvent instance.

    Raises:
        ET.ParseError: If the XML is malformed and cannot be parsed.
    """
    root = ET.fromstring(xml_str)
    warnings: list[str] = []

    # System fields
    event_id: Optional[int] = None
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
    event_data: dict[str, Any] = {}

    system_elem: Optional[ET.Element] = None
    event_data_elem: Optional[ET.Element] = None
    user_data_elem: Optional[ET.Element] = None

    for child in root:
        clean_tag = _strip_tag_namespace(child.tag)
        if clean_tag == "System":
            system_elem = child
        elif clean_tag == "EventData":
            event_data_elem = child
        elif clean_tag == "UserData":
            user_data_elem = child

    if system_elem is None:
        warnings.append("System element is missing from event XML")
    else:
        for elem in system_elem:
            tag = _strip_tag_namespace(elem.tag)
            text_val = (elem.text or "").strip()

            if tag == "Provider":
                provider = elem.attrib.get("Name")
                if not provider:
                    warnings.append("Provider Name attribute is missing")
            elif tag == "EventID":
                try:
                    event_id = int(text_val)
                except (ValueError, TypeError):
                    warnings.append(f"EventID is not a valid integer: '{text_val}'")
            elif tag == "EventRecordID":
                try:
                    record_id = int(text_val)
                except (ValueError, TypeError):
                    warnings.append(f"EventRecordID is not a valid integer: '{text_val}'")
            elif tag == "TimeCreated":
                timestamp_original = elem.attrib.get("SystemTime")
                dt, warn = parse_systemtime_string(timestamp_original)
                timestamp_utc = dt
                if warn:
                    warnings.append(warn)
            elif tag == "Channel":
                channel = text_val if text_val else None
            elif tag == "Computer":
                computer = text_val if text_val else None
            elif tag == "Level":
                try:
                    level = int(text_val)
                except (ValueError, TypeError):
                    warnings.append(f"Level is not an integer: '{text_val}'")
            elif tag == "Task":
                try:
                    task = int(text_val)
                except (ValueError, TypeError):
                    warnings.append(f"Task is not an integer: '{text_val}'")
            elif tag == "Opcode":
                try:
                    opcode = int(text_val)
                except (ValueError, TypeError):
                    warnings.append(f"Opcode is not an integer: '{text_val}'")
            elif tag == "Keywords":
                keywords = text_val if text_val else None
            elif tag == "Execution":
                pid_str = elem.attrib.get("ProcessID")
                tid_str = elem.attrib.get("ThreadID")
                if pid_str is not None:
                    try:
                        process_id = int(pid_str)
                    except ValueError:
                        warnings.append(f"ProcessID is not an integer: '{pid_str}'")
                if tid_str is not None:
                    try:
                        thread_id = int(tid_str)
                    except ValueError:
                        warnings.append(f"ThreadID is not an integer: '{tid_str}'")
            elif tag == "Security":
                user_sid = elem.attrib.get("UserID")

    # Audit for mandatory/expected fields that were missing
    if event_id is None:
        event_id = 0
        warnings.append("EventID was missing or invalid; recorded as 0")
    if record_id is None:
        warnings.append("EventRecordID is missing")
    if timestamp_utc is None and "TimeCreated SystemTime is missing or empty" not in warnings:
        warnings.append("Timestamp UTC is missing")
    if computer is None:
        warnings.append("Computer name is missing")
    if channel is None:
        warnings.append("Channel is missing")

    # Extract EventData
    if event_data_elem is not None:
        _extract_event_data(event_data_elem, event_data)

    # Extract UserData
    if user_data_elem is not None:
        _extract_user_data(user_data_elem, event_data)

    return NormalizedEvent(
        source_file=source_file,
        file_record_num=file_record_num,
        record_id=record_id,
        event_id=event_id,
        timestamp_utc=timestamp_utc,
        timestamp_original=timestamp_original,
        provider=provider,
        channel=channel,
        computer=computer,
        level=level,
        task=task,
        opcode=opcode,
        keywords=keywords,
        process_id=process_id,
        thread_id=thread_id,
        user_sid=user_sid,
        event_data=event_data,
        warnings=warnings,
    )


def parse_evtx(file_path: str | Path) -> tuple[list[NormalizedEvent], ParseSummary]:
    """Parse an EVTX file into NormalizedEvent instances and a ParseSummary.

    Verifies file magic bytes, streams chunk records, handles corrupt records
    gracefully without crashing, and records all issues in ParseSummary.

    Args:
        file_path: Path to the Windows EVTX log file.

    Returns:
        Tuple of (list_of_normalized_events, parse_summary).
    """
    path = Path(file_path)
    summary = ParseSummary()
    events: list[NormalizedEvent] = []

    if not path.is_file():
        summary.file_error = f"File not found or not a regular file: {path}"
        logger.error(summary.file_error)
        return events, summary

    # Verify EVTX magic header
    try:
        with open(path, "rb") as f:
            header = f.read(8)
            if header != EVTX_MAGIC:
                summary.file_error = (
                    f"Invalid EVTX magic header in '{path.name}'. "
                    f"Expected {EVTX_MAGIC!r}, got {header!r}"
                )
                logger.error(summary.file_error)
                return events, summary
    except Exception as exc:
        summary.file_error = f"Error opening file '{path}': {exc}"
        logger.error(summary.file_error)
        return events, summary

    # Parse records using python-evtx
    try:
        with evtx.Evtx(str(path)) as log:
            try:
                for chunk in log.chunks():
                    try:
                        for record in chunk.records():
                            summary.records_seen += 1
                            rec_num: Optional[int] = None
                            try:
                                rec_num = record.record_num()
                            except Exception:
                                pass

                            try:
                                xml_content = record.xml()
                                norm_event = normalize_event_xml(
                                    xml_str=xml_content,
                                    source_file=path.name,
                                    file_record_num=rec_num,
                                )
                                events.append(norm_event)
                                summary.records_parsed += 1
                            except ET.ParseError as pe:
                                summary.records_failed += 1
                                err_msg = f"Record #{rec_num or summary.records_seen} XML parse error: {pe}"
                                summary.errors.append(err_msg)
                                logger.warning(err_msg)
                            except Exception as re_exc:
                                summary.records_failed += 1
                                err_msg = f"Record #{rec_num or summary.records_seen} extraction error: {re_exc}"
                                summary.errors.append(err_msg)
                                logger.warning(err_msg)

                    except Exception as chunk_rec_err:
                        err_msg = f"Error iterating records in chunk: {chunk_rec_err}"
                        summary.errors.append(err_msg)
                        logger.warning(err_msg)

            except Exception as chunks_err:
                err_msg = f"Chunk-level failure while parsing '{path.name}': {chunks_err}"
                summary.file_error = err_msg
                logger.error(err_msg)

    except Exception as evtx_init_err:
        summary.file_error = f"EVTX initialization error on '{path.name}': {evtx_init_err}"
        logger.error(summary.file_error)

    return events, summary


def export_json(events: list[NormalizedEvent], output_path: str | Path, indent: int = 2) -> None:
    """Export normalized events to a JSON file.

    Args:
        events: List of normalized events to export.
        output_path: Path where JSON will be written.
        indent: JSON indentation spaces.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [event.to_dict() for event in events]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=indent, ensure_ascii=False)


def export_csv(events: list[NormalizedEvent], output_path: str | Path) -> None:
    """Export normalized events to a CSV file with spreadsheet formula injection protection.

    Args:
        events: List of normalized events to export.
        output_path: Path where CSV will be written.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "source_file",
        "file_record_num",
        "record_id",
        "event_id",
        "timestamp_utc",
        "timestamp_original",
        "provider",
        "channel",
        "computer",
        "level",
        "task",
        "opcode",
        "keywords",
        "process_id",
        "thread_id",
        "user_sid",
        "event_data",
        "warnings",
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            row = {
                "source_file": _sanitize_for_csv(event.source_file),
                "file_record_num": event.file_record_num,
                "record_id": event.record_id,
                "event_id": event.event_id,
                "timestamp_utc": (
                    event.timestamp_utc.isoformat() if event.timestamp_utc else ""
                ),
                "timestamp_original": _sanitize_for_csv(event.timestamp_original or ""),
                "provider": _sanitize_for_csv(event.provider or ""),
                "channel": _sanitize_for_csv(event.channel or ""),
                "computer": _sanitize_for_csv(event.computer or ""),
                "level": event.level,
                "task": event.task,
                "opcode": event.opcode,
                "keywords": _sanitize_for_csv(event.keywords or ""),
                "process_id": event.process_id,
                "thread_id": event.thread_id,
                "user_sid": _sanitize_for_csv(event.user_sid or ""),
                "event_data": _sanitize_for_csv(json.dumps(event.event_data, ensure_ascii=False)),
                "warnings": _sanitize_for_csv("; ".join(event.warnings)),
            }
            writer.writerow(row)
