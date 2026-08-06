"""EVTX to normalised events.

Windows writes the same conceptual fact in different shapes depending on which
channel recorded it: Sysmon calls the running binary `Image`, the Security log
calls it `ProcessName`, and PowerShell script block logging has no process
context at all. Detectors should not have to know that, so everything is
flattened here into one shape and the original record is carried along intact
for `alert.raw`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from evtx import PyEvtxParser

# Channel name -> the short source label stored on alert.source
CHANNELS = {
    "Microsoft-Windows-Sysmon/Operational": "sysmon",
    "Microsoft-Windows-PowerShell/Operational": "powershell",
    "Security": "security",
    "System": "system",
}


@dataclass(frozen=True)
class Event:
    """One Windows event, flattened enough for a detector to reason about."""

    source: str
    event_id: int
    observed_at: datetime
    host: str
    record_id: int
    user: str | None = None
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    target_image: str | None = None
    target_object: str | None = None
    granted_access: str | None = None
    destination_ip: str | None = None
    destination_port: str | None = None
    script_block: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def process_name(self) -> str:
        """Bare executable name, lowercased. Most rules only care about this."""
        return Path(self.image).name.lower() if self.image else ""

    @property
    def parent_name(self) -> str:
        return Path(self.parent_image).name.lower() if self.parent_image else ""

    @property
    def target_name(self) -> str:
        return Path(self.target_image).name.lower() if self.target_image else ""


def _first(data: dict[str, Any], *keys: str) -> str | None:
    """Return the first key present and non-empty. Field names vary by channel."""
    for key in keys:
        value = data.get(key)
        if value not in (None, "", "-"):
            return str(value)
    return None


def _parse_time(system: dict[str, Any]) -> datetime:
    stamp = system.get("TimeCreated", {}).get("#attributes", {}).get("SystemTime")
    if not stamp:
        return datetime.min
    # Python's parser rejects the Z suffix before 3.11 and chokes on the
    # 7-digit fractional seconds Windows sometimes writes.
    stamp = stamp.replace("Z", "+00:00")
    if "." in stamp:
        head, _, tail = stamp.partition(".")
        digits = "".join(c for c in tail if c.isdigit())[:6]
        offset = tail[len(digits) :] if not tail[len(digits) :].isdigit() else ""
        stamp = f"{head}.{digits:<06s}{offset or '+00:00'}"
    return datetime.fromisoformat(stamp)


def normalise(record: dict[str, Any]) -> Event | None:
    """Turn one parsed EVTX record into an Event, or None if unusable."""
    event = record.get("Event")
    if not isinstance(event, dict):
        return None

    system = event.get("System", {})
    data = event.get("EventData") or {}
    if not isinstance(data, dict):
        data = {"raw": data}

    channel = system.get("Channel", "")
    event_id = system.get("EventID")
    if event_id is None:
        return None

    return Event(
        source=CHANNELS.get(channel, channel.lower() or "unknown"),
        event_id=int(event_id),
        observed_at=_parse_time(system),
        host=system.get("Computer", "unknown"),
        record_id=int(system.get("EventRecordID") or 0),
        user=_first(data, "User", "SubjectUserName", "TargetUserName"),
        image=_first(data, "Image", "NewProcessName", "ProcessName", "SourceImage"),
        command_line=_first(data, "CommandLine", "ProcessCommandLine"),
        parent_image=_first(data, "ParentImage", "ParentProcessName"),
        parent_command_line=_first(data, "ParentCommandLine"),
        target_image=_first(data, "TargetImage", "TargetProcessName"),
        target_object=_first(data, "TargetObject", "ObjectName", "TaskName"),
        granted_access=_first(data, "GrantedAccess", "AccessMask"),
        destination_ip=_first(data, "DestinationIp", "DestinationIsIpv6"),
        destination_port=_first(data, "DestinationPort"),
        script_block=_first(data, "ScriptBlockText"),
        data=data,
        raw=event,
    )


def read_evtx(path: Path) -> Iterator[Event]:
    """Yield normalised events from one .evtx file, oldest first."""
    parser = PyEvtxParser(str(path))
    for record in parser.records_json():
        try:
            payload = json.loads(record["data"])
        except (json.JSONDecodeError, KeyError):
            continue
        event = normalise(payload)
        if event is not None:
            yield event


def read_directory(directory: Path) -> list[Event]:
    """Read every .evtx under a directory, sorted into one chronological stream."""
    events: list[Event] = []
    for path in sorted(directory.glob("*.evtx")):
        events.extend(read_evtx(path))
    events.sort(key=lambda e: e.observed_at)
    return events
