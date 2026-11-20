"""Unit tests for ForensicTrail XML normalization and EVTX parsing."""

from datetime import datetime, timezone
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from src.models import NormalizedEvent, ParseSummary
from src.parser import (
    _sanitize_for_csv,
    export_csv,
    export_json,
    normalize_event_xml,
    parse_evtx,
    parse_systemtime_string,
)

# Synthetic XML fixtures adhering to rule 9 (*.example.test, 192.0.2.0/24)
SYNTHETIC_SECURITY_4624_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-19T14:30:00.1234567Z" />
    <EventRecordID>1001</EventRecordID>
    <Correlation ActivityID="{00000000-0000-0000-0000-000000000000}" />
    <Execution ProcessID="688" ThreadID="1204" />
    <Channel>Security</Channel>
    <Computer>WKSTN01.example.test</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">WKSTN01$</Data>
    <Data Name="TargetUserName">analyst.alice</Data>
    <Data Name="TargetDomainName">EXAMPLE</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="IpAddress">192.0.2.55</Data>
    <Data Name="IpPort">49152</Data>
  </EventData>
</Event>"""

SYNTHETIC_EVENT_1102_USERDATA_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" />
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <Opcode>0</Opcode>
    <Keywords>0x4020000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-19T15:00:00.0000000Z" />
    <EventRecordID>2005</EventRecordID>
    <Execution ProcessID="1024" ThreadID="2048" />
    <Channel>Security</Channel>
    <Computer>DC01.example.test</Computer>
    <Security />
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-999-888-777-500</SubjectUserSid>
      <SubjectUserName>AdminUser</SubjectUserName>
      <SubjectDomainName>EXAMPLE</SubjectDomainName>
      <SubjectLogonId>0x3e7</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>"""

SYNTHETIC_DUPLICATES_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-10-19T16:00:00.000000Z" />
    <EventRecordID>3001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>SRV01.example.test</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetUserName">bob_secondary</Data>
    <Data Name="TargetUserName">bob_tertiary</Data>
    <Data>unnamed_first</Data>
    <Data>unnamed_second</Data>
  </EventData>
</Event>"""

SYNTHETIC_MINIMAL_MISSING_FIELDS_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
  </System>
</Event>"""


def test_normalize_core_fields() -> None:
    """Validate extraction of all core fields from synthetic Windows Event XML."""
    event = normalize_event_xml(
        xml_str=SYNTHETIC_SECURITY_4624_XML,
        source_file="Security.evtx",
        file_record_num=42,
    )

    assert event.source_file == "Security.evtx"
    assert event.file_record_num == 42
    assert event.record_id == 1001
    assert event.event_id == 4624
    assert event.provider == "Microsoft-Windows-Security-Auditing"
    assert event.channel == "Security"
    assert event.computer == "WKSTN01.example.test"
    assert event.level == 0
    assert event.task == 12544
    assert event.opcode == 0
    assert event.keywords == "0x8020000000000000"
    assert event.process_id == 688
    assert event.thread_id == 1204
    assert event.user_sid == "S-1-5-18"
    assert event.timestamp_original == "2026-10-19T14:30:00.1234567Z"
    assert event.timestamp_utc == datetime(2026, 10, 19, 14, 30, 0, 123456, tzinfo=timezone.utc)

    # EventData fields
    assert event.event_data["TargetUserName"] == "analyst.alice"
    assert event.event_data["IpAddress"] == "192.0.2.55"
    assert event.event_data["LogonType"] == "2"
    assert len(event.warnings) == 0


def test_normalize_duplicates_and_unnamed_data() -> None:
    """Verify duplicate Data names receive _2, _3 suffixes and unnamed Data keys."""
    event = normalize_event_xml(
        xml_str=SYNTHETIC_DUPLICATES_XML,
        source_file="Security.evtx",
        file_record_num=50,
    )

    assert event.event_data["TargetUserName"] == "bob"
    assert event.event_data["TargetUserName_2"] == "bob_secondary"
    assert event.event_data["TargetUserName_3"] == "bob_tertiary"
    assert event.event_data["Data"] == "unnamed_first"
    assert event.event_data["Data_2"] == "unnamed_second"


def test_normalize_userdata_event_1102() -> None:
    """Verify UserData XML structure (e.g. Event 1102) flattens into event_data."""
    event = normalize_event_xml(
        xml_str=SYNTHETIC_EVENT_1102_USERDATA_XML,
        source_file="Security.evtx",
        file_record_num=99,
    )

    assert event.event_id == 1102
    assert event.record_id == 2005
    assert event.computer == "DC01.example.test"
    assert event.event_data["SubjectUserName"] == "AdminUser"
    assert event.event_data["SubjectDomainName"] == "EXAMPLE"
    assert event.event_data["SubjectLogonId"] == "0x3e7"
    assert event.event_data["SubjectUserSid"] == "S-1-5-21-999-888-777-500"


def test_normalize_missing_fields() -> None:
    """Verify missing fields become None and populate warning list without fabricating data."""
    event = normalize_event_xml(
        xml_str=SYNTHETIC_MINIMAL_MISSING_FIELDS_XML,
        source_file="Security.evtx",
    )

    assert event.event_id == 4624
    assert event.record_id is None
    assert event.timestamp_utc is None
    assert event.timestamp_original is None
    assert event.computer is None
    assert event.channel is None
    assert event.provider is None
    assert event.event_data == {}

    # Verify warnings recorded
    assert any("EventRecordID is missing" in w for w in event.warnings)
    assert any("Computer name is missing" in w for w in event.warnings)
    assert any("Channel is missing" in w for w in event.warnings)
    assert any("TimeCreated" in w or "Timestamp" in w for w in event.warnings)


def test_timestamp_parsing_7_digit_precision() -> None:
    """Verify 7-digit fractional seconds are truncated to 6 (microsecond precision)."""
    raw_time = "2026-10-19T14:30:00.1234567Z"
    dt, warn = parse_systemtime_string(raw_time)

    assert warn is None
    assert dt is not None
    assert dt.microsecond == 123456
    assert dt.year == 2026
    assert dt.hour == 14
    assert dt.tzinfo == timezone.utc


def test_timestamp_parsing_various_formats() -> None:
    """Verify handling of diverse timestamp formats and bad inputs."""
    # No fractional seconds
    dt1, warn1 = parse_systemtime_string("2026-10-19T14:30:00Z")
    assert warn1 is None
    assert dt1 == datetime(2026, 10, 19, 14, 30, 0, tzinfo=timezone.utc)

    # Empty string
    dt_empty, warn_empty = parse_systemtime_string("")
    assert dt_empty is None
    assert "missing or empty" in warn_empty

    # Invalid timestamp string
    dt_inv, warn_inv = parse_systemtime_string("invalid-date-format")
    assert dt_inv is None
    assert "Failed to parse timestamp" in warn_inv


def test_malformed_xml_raises_parse_error() -> None:
    """Verify normalize_event_xml raises ET.ParseError when XML is corrupt."""
    bad_xml = "<Event><System><EventID>4624</EventID>"  # Unclosed tags
    with pytest.raises(ET.ParseError):
        normalize_event_xml(bad_xml, source_file="Security.evtx")


def test_parse_evtx_non_evtx_file(tmp_path: Path) -> None:
    """Verify parse_evtx detects invalid magic bytes and never raises."""
    fake_file = tmp_path / "corrupted.evtx"
    fake_file.write_bytes(b"NOT_AN_EVTX_FILE_CONTENT")

    events, summary = parse_evtx(fake_file)

    assert len(events) == 0
    assert summary.records_seen == 0
    assert summary.records_parsed == 0
    assert summary.file_error is not None
    assert "Invalid EVTX magic header" in summary.file_error


def test_parse_evtx_missing_file(tmp_path: Path) -> None:
    """Verify parse_evtx handles missing files gracefully without raising."""
    non_existent = tmp_path / "does_not_exist.evtx"

    events, summary = parse_evtx(non_existent)

    assert len(events) == 0
    assert summary.file_error is not None
    assert "File not found" in summary.file_error


def test_export_json_and_csv(tmp_path: Path) -> None:
    """Verify export_json and export_csv serialize events and neutralize formula injection."""
    event = normalize_event_xml(
        xml_str=SYNTHETIC_SECURITY_4624_XML,
        source_file="Security.evtx",
        file_record_num=1,
    )
    # Add a potentially hostile spreadsheet formula to test neutralization
    event.computer = "=cmd|' /C calc'!A0"

    json_path = tmp_path / "export.json"
    csv_path = tmp_path / "export.csv"

    export_json([event], json_path)
    export_csv([event], csv_path)

    assert json_path.exists()
    assert csv_path.exists()

    # Verify JSON content
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["event_id"] == 4624
    assert data[0]["record_id"] == 1001

    # Verify CSV neutralization (prepends single quote)
    csv_content = csv_path.read_text(encoding="utf-8")
    assert "'=cmd|' /C calc'!A0" in csv_content


def test_sanitize_for_csv() -> None:
    """Verify spreadsheet formula prefixes are safely neutralised."""
    assert _sanitize_for_csv("=1+1") == "'=1+1"
    assert _sanitize_for_csv("+calc") == "'+calc"
    assert _sanitize_for_csv("-100") == "'-100"
    assert _sanitize_for_csv("@SUM(A1:A5)") == "'@SUM(A1:A5)"
    assert _sanitize_for_csv("benign_text") == "benign_text"
    assert _sanitize_for_csv(1234) == 1234
