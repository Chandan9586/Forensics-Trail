# 🔍 Forensics Trail: Offline Windows EVTX Digital Forensics & Incident Response Toolkit

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Pytest](https://img.shields.io/badge/Tests-11%20Passing-brightgreen.svg?logo=pytest&logoColor=white)](https://pytest.org)
[![python-evtx](https://img.shields.io/badge/Parser-python--evtx%200.8%2B-orange.svg)](https://github.com/williballenthin/python-evtx)
[![DFIR](https://img.shields.io/badge/DFIR-Windows%20Event%20Logs-crimson.svg)](https://github.com/Chandan9586/Forensics-Trail)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Forensics Trail** is a lightweight, high-integrity Digital Forensics and Incident Response (DFIR) toolkit engineered for security analysts and forensicators. It parses raw Windows XML Event Log files (`.evtx`), verifies binary file magic bytes (`ElfFile\0`), normalizes unstructured XML chunks into strongly-typed dataclasses, extracts UserData and EventData payloads, sanitizes exports against spreadsheet formula injection attacks, and produces clean JSON, CSV, and human-readable forensic summary reports without altering original evidence files.

---

## 📑 Table of Contents
- [Key Features](#-key-features)
- [Architecture & Normalization Pipeline](#-architecture--normalization-pipeline)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Quick Start Guide](#-quick-start-guide)
- [Forensic CLI Runner (`run_evtx.py`)](#-forensic-cli-runner-runevtxpy)
- [Python API Usage](#-python-api-usage)
- [Normalized Data Schema](#-normalized-data-schema)
- [Forensic Evidence Integrity & Security](#-forensic-evidence-integrity--security)
- [Supported Windows Event Telemetry](#-supported-windows-event-telemetry)
- [Automated Testing](#-automated-testing)
- [Contributing & License](#-contributing--license)

---

## 🌟 Key Features

- **🔒 Evidence Integrity by Design**: Original evidence files are opened exclusively in read-only binary mode (`rb`). Pre-execution header magic validation (`b'ElfFile\x00'`) verifies log authenticity prior to chunk processing.
- **⚡ Resilient Chunk Streaming**: Powered by `python-evtx`, streaming binary records across chunks with robust per-record error boundary isolation. Corrupt, truncated, or malformed XML records are caught and recorded in `ParseSummary` without crashing batch analysis.
- **⏱️ High-Precision Timestamp Truncation**: Windows SystemTime attributes frequently contain 7 decimal digits (100ns precision). Forensics Trail normalizes and safely truncates sub-second values to 6 decimal digits (microsecond precision) for UTC `datetime` objects while retaining the original raw timestamp for legal audit trails.
- **🧩 Deep EventData & UserData Extraction**: Handles named XML `<Data Name="...">` attributes, hierarchical `<UserData>` blocks (e.g., Event 1102 audit log clears), and automatically handles duplicate or unnamed `<Data>` elements using sequential collision indexing (`_2`, `_3`).
- **🛡️ Spreadsheet Formula Injection Defense**: Neutralizes CSV formula injection vulnerabilities (`=`, `+`, `-`, `@` triggers) across all exported columns, safeguarding spreadsheet-based analyst workstations from weaponized strings in usernames, paths, or machine names.
- **📊 Standardized Multi-Format Export**: One-click export to nested JSON (`NormalizedEvent.to_dict()`) and flat CSV formats optimized for SIEM ingestion, Splunk forwarders, Elastic Logstash, or Pandas forensic notebooks.
- **📋 Automated Triage Reporting**: Compiles statistical forensic summaries displaying records processed, health metrics, earliest/latest timestamps, and distributions of top EventIDs, Channels, Computers, and Providers.

---

## 🛠 Architecture & Normalization Pipeline

```text
+-------------------------------------------------------------------------+
|                     Raw Windows EVTX Evidence File                      |
|              (Binary: Chunk Headers, String Tables, BXML)               |
+------------------------------------+------------------------------------+
                                     | Read-Only Binary Stream (ElfFile\0)
                                     v
+-------------------------------------------------------------------------+
|                       python-evtx Streaming Engine                      |
|      (Chunk Verification, Record Chunk Traverser, Raw XML Output)       |
+------------------------------------+------------------------------------+
                                     | Raw XML Record Strings
                                     v
+-------------------------------------------------------------------------+
|                  Pure XML Normalizer (normalize_event_xml)              |
|  +--------------------+  +--------------------+  +--------------------+ |
|  |   System Header    |  |  EventData / User  |  | Timestamp Truncate | |
|  | (EventID, RecordID)|  | (Payload Flatten)  |  |  (100ns -> Micro)  | |
|  +--------------------+  +--------------------+  +--------------------+ |
+------------------------------------+------------------------------------+
                                     | NormalizedEvent Dataclass
                                     v
+-------------------------------------------------------------------------+
|                       Forensic Export & Audit Engine                    |
|  +--------------------+  +--------------------+  +--------------------+ |
|  |    JSON Exporter   |  | CSV Safe Exporter  |  |  Summary Reporter  | |
|  | (to_dict / Nested) |  | (Formula Sanitized)|  | (Triage Telemetry) | |
|  +--------------------+  +--------------------+  +--------------------+ |
+------------------------------------+------------------------------------+
                                     |
                +--------------------+--------------------+
                v                                         v
+-------------------------------+         +-------------------------------+
|      JSON & CSV Artifacts     |         |     Forensic Summary Report   |
|  (SIEM, Splunk, Pandas Ready) |         |     (Incident Triage Logs)    |
+-------------------------------+         +-------------------------------+
```

* **Core Language**: Python 3.10+ (tested on Python 3.13)
* **Binary Parser Engine**: [`python-evtx`](https://github.com/williballenthin/python-evtx)
* **XML Processing**: Python Standard Library `xml.etree.ElementTree`
* **Data Models**: Python `@dataclass(slots=True)`
* **Test Suite**: [PyTest 8.0+](https://pytest.org)

---

## 📂 Project Structure

```text
Forensics-Trail/
├── src/
│   ├── __init__.py           # Package initialization & version metadata
│   ├── models.py             # Strongly-typed dataclasses (NormalizedEvent, ParseSummary)
│   └── parser.py             # EVTX streaming, pure XML normalizer, CSV/JSON exporters
├── tests/
│   ├── __init__.py           # Unit test package initialization
│   ├── test_parser.py        # 11 unit tests covering normalization, edge cases & exports
│   └── fixtures/             # Test fixtures & synthetic logs directory (.gitkeep)
├── docs/                     # Documentation assets & notes (.gitkeep)
├── evidence/                 # Dedicated local directory for case evidence (git-ignored)
├── reports/                  # Generated JSON, CSV, and text forensic summaries (git-ignored)
├── rules/                    # Threat detection & correlation rules directory (.gitkeep)
├── samples/                  # Sample test EVTX logs directory (.gitkeep)
├── run_evtx.py               # CLI runner for parsing EVTX logs & generating reports
├── requirements.txt          # Python runtime dependencies
├── .gitignore                # Git exclusions (EVTX evidence, reports, bytecode)
└── README.md                 # Project documentation
```

---

## ⚡ Prerequisites

Ensure you have the following installed:
* **Python 3.10+** (tested and verified on Python 3.13)
* **Git**
* Windows, Linux, or macOS environment

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone https://github.com/Chandan9586/Forensics-Trail.git
cd Forensics-Trail
```

### 2. Set Up a Virtual Environment (Recommended)
```bash
# On Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

# On Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 💻 Forensic CLI Runner (`run_evtx.py`)

Run the pre-configured CLI runner against any EVTX file. It performs integrity validation, extracts records, exports JSON/CSV artifacts to the `reports/` folder, and prints an executive summary:

```bash
# Parse a specific EVTX log file
python run_evtx.py "C:\Path\To\Security.evtx"

# Specify a custom report output directory
python run_evtx.py "C:\Path\To\System.evtx" --output-dir ./case_001_reports
```

### Sample Terminal Execution Output:
```text
[*] ForensicTrail EVTX Runner
[*] Target file: C:\Users\analyst\Documents\sample_logs.evtx
[*] Verified file is readable. Header magic: b'ElfFile\x00'
[*] Parsing EVTX records...
[*] Exporting 11 events to JSON: ./reports/sample_logs_events.json
[*] Exporting 11 events to CSV: ./reports/sample_logs_events.csv

======================================================================
              FORENSICSTRAIL - EVTX PARSE SUMMARY REPORT
======================================================================
Generated At          : 2026-11-20T12:00:00.000000
Input EVTX File       : C:\Users\analyst\Documents\sample_logs.evtx
File Size             : 69,632 bytes
----------------------------------------------------------------------
EXECUTION METRICS:
  Total Records Seen  : 11
  Records Parsed OK   : 11
  Records Failed      : 0
  File Level Error    : None
----------------------------------------------------------------------
ERRORS ENCOUNTERED    : None (0 errors)
----------------------------------------------------------------------
TELEMETRY OVERVIEW:
  Earliest Event Time : 2026-10-29T12:37:51.341976+00:00
  Latest Event Time   : 2026-10-29T17:03:12.366154+00:00

Top Event IDs:
  EventID 0      :     3 event(s)
  EventID 16384  :     2 event(s)
  EventID 1001   :     2 event(s)
  EventID 8233   :     1 event(s)
  EventID 16394  :     1 event(s)

Channels:
  Application               :    11 event(s)

Computers:
  WORKSTATION-01            :    11 event(s)
----------------------------------------------------------------------
OUTPUT ARTIFACTS:
  JSON Export : ./reports/sample_logs_events.json
  CSV Export  : ./reports/sample_logs_events.csv
  Text Report : ./reports/sample_logs_summary_report.txt
======================================================================
```

---

## 🐍 Python API Usage

Forensics Trail modules are clean, stateless, and directly importable into your custom DFIR scripts, Jupyter notebooks, or SOAR pipelines:

```python
from pathlib import Path
from src.parser import parse_evtx, export_json, export_csv

# 1. Parse raw EVTX log
evtx_path = Path("evidence/Security.evtx")
events, summary = parse_evtx(evtx_path)

print(f"Successfully parsed {summary.records_parsed}/{summary.records_seen} records.")

# 2. Iterate normalized events
for event in events:
    if event.event_id == 4624:
        logon_type = event.event_data.get("LogonType")
        user = event.event_data.get("TargetUserName")
        ip = event.event_data.get("IpAddress")
        print(f"[{event.timestamp_utc}] Logon 4624: User={user} Type={logon_type} IP={ip}")

# 3. Export to JSON & CSV
export_json(events, "reports/security_events.json")
export_csv(events, "reports/security_events.csv")
```

---

## 📊 Normalized Data Schema

All parsed events are mapped into a standardized `NormalizedEvent` dataclass:

| Field | Type | Description |
|:---|:---|:---|
| `source_file` | `str` | Name of originating `.evtx` file. |
| `file_record_num`| `int \| None` | Sequential record number reported by EVTX chunk index. |
| `record_id` | `int \| None` | Windows `EventRecordID` identifier. |
| `event_id` | `int` | Windows Event ID (e.g., `4624`, `4625`, `1102`). |
| `timestamp_utc` | `datetime \| None` | Timezone-aware UTC timestamp truncated to microsecond precision. |
| `timestamp_original` | `str \| None` | Verbatim SystemTime string from raw XML attribute. |
| `provider` | `str \| None` | Event logging provider (e.g., `Microsoft-Windows-Security-Auditing`). |
| `channel` | `str \| None` | Log channel (`Security`, `System`, `Application`). |
| `computer` | `str \| None` | Fully qualified domain or hostname of logging system. |
| `level` | `int \| None` | Severity level (1=Critical, 2=Error, 3=Warning, 4=Info). |
| `task` | `int \| None` | Task category integer code. |
| `opcode` | `int \| None` | Opcode operation indicator. |
| `keywords` | `str \| None` | Hexadecimal keyword mask (e.g., `0x8020000000000000`). |
| `process_id` | `int \| None` | Execution process ID logging the record. |
| `thread_id` | `int \| None` | Execution thread ID. |
| `user_sid` | `str \| None` | Security Identifier (SID) of the executing user context. |
| `event_data` | `dict[str, Any]` | Flattened key-value map of all EventData and UserData tags. |
| `warnings` | `list[str]` | Non-fatal anomaly audit warnings (missing fields, duplicate keys). |

---

## 🛡️ Forensic Evidence Integrity & Security

### 1. Non-Destructive Read-Only Evidence Access
Evidence preservation is paramount in digital investigations. Forensics Trail opens EVTX files with `open(path, 'rb')` exclusively, ensuring original file modification timestamps (`mtime`), metadata, and byte content remain untouched.

### 2. Spreadsheet Formula Injection (CSV Injection) Protection
Forensic logs often contain adversary-controlled strings (e.g., malicious usernames `=cmd|' /C calc'!A0` or computer names). When viewing CSV exports in Microsoft Excel or LibreOffice Calc, unescaped formulas can trigger remote command execution. 

Forensics Trail implements the `_sanitize_for_csv()` defense:
```python
def _sanitize_for_csv(val: Any) -> Any:
    if isinstance(val, str) and val.startswith(("=", "+", "-", "@")):
        return f"'{val}"
    return val
```
Any field beginning with dangerous formula triggers is safely prepended with a single quote (`'`), ensuring spreadsheet software treats the content purely as inert text.

### 3. Graceful Failure & Corrupt Chunk Recovery
Windows Event Logs can suffer from corruption during ungraceful shutdowns or deliberate anti-forensic tampering. If a chunk or record fails XML validation, the error is appended to `ParseSummary.errors`, leaving valid records intact.

---

## 🔬 Supported Windows Event Telemetry

Forensics Trail normalizes any valid EVTX record, with first-class support for core DFIR event categories:

| Event ID | Provider / Category | Forensic Significance |
|:---|:---|:---|
| **`4624`** | Security-Auditing | Successful Account Logon (Logon Types: 2=Interactive, 3=Network, 10=RDP). |
| **`4625`** | Security-Auditing | Failed Account Logon (Brute-force & credential stuffing detection). |
| **`4672`** | Security-Auditing | Special Privileges Assigned to New Logon (Admin rights elevation). |
| **`4688`** | Security-Auditing | New Process Created (Parent/Child process command line execution). |
| **`7045`** | System (Service Control) | New Windows Service Installed (Persistence & lateral movement). |
| **`1102`** | Eventlog (UserData) | Security Audit Log Was Cleared (Anti-forensics tampering). |
| **`1001`** | Windows Error Reporting | Application Crash or Update Failure telemetry. |
| **`8233 / 16384`** | Security-SPP | Software Protection & License Verification operations. |

---

## 🧪 Automated Testing

Forensics Trail features a comprehensive PyTest test suite testing XML normalization, edge cases, error recovery, and CSV sanitization against synthetic fixtures adhering to RFC 2606 standards:

```bash
# Run tests with verbose output
pytest -v
```

### Test Coverage Highlights:
- `test_normalize_core_fields`: Full extraction of all header and event data fields.
- `test_normalize_duplicates_and_unnamed_data`: Auto-incrementing duplicate keys (`_2`, `_3`) and unnamed data tags.
- `test_normalize_userdata_event_1102`: Dynamic flattening of nested `<UserData>` elements.
- `test_normalize_missing_fields`: Graceful population of missing fields without raising exceptions.
- `test_timestamp_parsing_7_digit_precision`: Accurate truncation of 7-digit 100ns precision timestamps.
- `test_timestamp_parsing_various_formats`: Handling UTC trailing 'Z', ISO formats, and empty strings.
- `test_malformed_xml_raises_parse_error`: Accurate parse error isolation on corrupted XML.
- `test_parse_evtx_non_evtx_file`: Binary header validation rejecting invalid non-EVTX files.
- `test_parse_evtx_missing_file`: Graceful handling of non-existent file paths.
- `test_export_json_and_csv`: Full serialization check and file output creation.
- `test_sanitize_for_csv`: Verification of formula injection prefix neutralization.

```text
tests/test_parser.py::test_normalize_core_fields PASSED                  [  9%]
tests/test_parser.py::test_normalize_duplicates_and_unnamed_data PASSED  [ 18%]
tests/test_parser.py::test_normalize_userdata_event_1102 PASSED          [ 27%]
tests/test_parser.py::test_normalize_missing_fields PASSED               [ 36%]
tests/test_parser.py::test_timestamp_parsing_7_digit_precision PASSED    [ 45%]
tests/test_parser.py::test_timestamp_parsing_various_formats PASSED      [ 54%]
tests/test_parser.py::test_malformed_xml_raises_parse_error PASSED       [ 63%]
tests/test_parser.py::test_parse_evtx_non_evtx_file PASSED               [ 72%]
tests/test_parser.py::test_parse_evtx_missing_file PASSED                [ 81%]
tests/test_parser.py::test_export_json_and_csv PASSED                    [ 90%]
tests/test_parser.py::test_sanitize_for_csv PASSED                       [100%]

============================= 11 passed in 0.10s ==============================
```

---

## 🤝 Contributing

Contributions, bug reports, and pull requests are welcome!

1. Fork the Project repository.
2. Create your Feature Branch (`git checkout -b feature/NewFeature`).
3. Commit your Changes (`git commit -m 'Add NewFeature'`).
4. Push to the Branch (`git push origin feature/NewFeature`).
5. Open a Pull Request.

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.
