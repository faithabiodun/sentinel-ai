"""Detection rules.

Deliberately not an LLM. These are cheap, deterministic, and explainable, which
means the agent starts from a signal it can trust and spends its reasoning on
the part that actually needs judgement — what the signals mean together.

Every rule carries the ATT&CK technique it maps to, so a firing rule already
supplies the technique for the timeline entry it produces.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .evtx_reader import Event

Severity = str  # matches the severity enum in db/schema.sql


@dataclass(frozen=True)
class Alert:
    """A rule firing on one event."""

    rule: str
    technique: str
    severity: Severity
    summary: str
    event: Event


Rule = Callable[[Event], Alert | None]
RULES: list[Rule] = []


def rule(fn: Rule) -> Rule:
    RULES.append(fn)
    return fn


# PROCESS_VM_READ. Reading another process's memory requires this bit, so
# testing for it catches every dumper regardless of what else it asked for.
# An earlier version of this rule enumerated known-bad mask values and missed
# 0x1f1fff, which is what meterpreter's hashdump actually requests.
PROCESS_VM_READ = 0x0010


def _can_read_memory(mask: str | None) -> bool:
    if not mask:
        return True  # absent mask — let the rule fire and be judged on context
    try:
        return bool(int(mask, 16) & PROCESS_VM_READ)
    except ValueError:
        return True

CREDENTIAL_TOOLING = re.compile(
    r"minidumpwritedump|invoke-mimikatz|sekurlsa|lsadump|gsecdump|procdump.{0,20}lsass"
    r"|comsvcs\.dll.{0,20}minidump|dumpert|nanodump",
    re.IGNORECASE,
)

ENCODED_POWERSHELL = re.compile(
    r"\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}"
    r"|frombase64string",
    re.IGNORECASE,
)

LOLBINS = {
    "rundll32.exe": "T1218.011",
    "mshta.exe": "T1218.005",
    "regsvr32.exe": "T1218.010",
    "msxsl.exe": "T1220",
    "installutil.exe": "T1218.004",
}

REMOTE_EXEC_PARENTS = {
    "wmiprvse.exe": ("T1047", "WMI remote execution"),
    "psexesvc.exe": ("T1021.002", "PsExec service execution"),
    "wsmprovhost.exe": ("T1021.006", "PowerShell Remoting"),
    "winrshost.exe": ("T1021.006", "WinRM remote shell"),
}


@rule
def lsass_process_access(event: Event) -> Alert | None:
    """Sysmon 10 — one process opening a readable handle on lsass."""
    if event.source != "sysmon" or event.event_id != 10:
        return None
    if event.target_name != "lsass.exe":
        return None

    if not _can_read_memory(event.granted_access):
        return None

    return Alert(
        rule="lsass_process_access",
        technique="T1003.001",
        severity="critical",
        summary=f"{event.process_name or 'a process'} opened a handle on lsass.exe "
        f"with access {event.granted_access}",
        event=event,
    )


@rule
def lsass_object_access(event: Event) -> Alert | None:
    """Security 4656/4663 — the same idea, seen through object access auditing."""
    if event.source != "security" or event.event_id not in (4656, 4663):
        return None
    if "lsass.exe" not in (event.target_object or "").lower():
        return None

    return Alert(
        rule="lsass_object_access",
        technique="T1003.001",
        severity="critical",
        summary=f"Handle requested on lsass.exe with access mask {event.granted_access}",
        event=event,
    )


@rule
def credential_tooling_in_script(event: Event) -> Alert | None:
    """PowerShell 4104 — script block naming a known credential-theft routine."""
    if event.event_id != 4104:
        return None

    block = event.script_block or ""
    match = CREDENTIAL_TOOLING.search(block)
    if not match:
        return None

    return Alert(
        rule="credential_tooling_in_script",
        technique="T1003.001",
        severity="critical",
        summary=f"PowerShell script block references {match.group(0)}",
        event=event,
    )


@rule
def encoded_powershell(event: Event) -> Alert | None:
    """Sysmon 1 — base64 payload on a PowerShell command line."""
    if event.source != "sysmon" or event.event_id != 1:
        return None
    if "powershell" not in event.process_name:
        return None

    command = event.command_line or ""
    if not ENCODED_POWERSHELL.search(command):
        return None

    return Alert(
        rule="encoded_powershell",
        technique="T1059.001",
        severity="high",
        summary="PowerShell launched with an encoded command",
        event=event,
    )


@rule
def lolbin_execution(event: Event) -> Alert | None:
    """Sysmon 1 — a signed Windows binary used to run something else."""
    if event.source != "sysmon" or event.event_id != 1:
        return None

    technique = LOLBINS.get(event.process_name)
    if technique is None:
        return None

    command = (event.command_line or "").lower()
    # rundll32 with no arguments at all is the noisier legitimate case.
    if event.process_name == "rundll32.exe" and len(command.split()) < 2:
        return None

    return Alert(
        rule="lolbin_execution",
        technique=technique,
        severity="medium",
        summary=f"{event.process_name} executed with arguments",
        event=event,
    )


@rule
def remote_execution_parent(event: Event) -> Alert | None:
    """Sysmon 1 — parent process implies the command arrived over the network."""
    if event.source != "sysmon" or event.event_id != 1:
        return None

    hit = REMOTE_EXEC_PARENTS.get(event.parent_name)
    if hit is None:
        return None

    technique, label = hit
    return Alert(
        rule="remote_execution_parent",
        technique=technique,
        severity="high",
        summary=f"{label}: {event.parent_name} spawned {event.process_name}",
        event=event,
    )


@rule
def scheduled_task_created(event: Event) -> Alert | None:
    """Security 4698 — a scheduled task is a durable foothold."""
    if event.source != "security" or event.event_id != 4698:
        return None

    return Alert(
        rule="scheduled_task_created",
        technique="T1053.005",
        severity="medium",
        summary=f"Scheduled task registered: {event.target_object or 'unnamed'}",
        event=event,
    )


@rule
def remote_thread_created(event: Event) -> Alert | None:
    """Sysmon 8 — code injected into another process."""
    if event.source != "sysmon" or event.event_id != 8:
        return None

    return Alert(
        rule="remote_thread_created",
        technique="T1055",
        severity="high",
        summary=f"Remote thread created in {event.target_name or 'another process'}",
        event=event,
    )


@rule
def pipe_connection(event: Event) -> Alert | None:
    """Sysmon 18 — named pipes are how PsExec and impacket carry a session."""
    if event.source != "sysmon" or event.event_id != 18:
        return None

    # ntsvcs is the Service Control Manager pipe — PsExec and its imitators
    # create their service over it. It carries legitimate local service traffic
    # too, so this rule is noisy by design and leans on entity memory to learn
    # which hosts do it routinely.
    pipe = (event.data.get("PipeName") or "").lower()
    if not any(m in pipe for m in ("psexesvc", "atsvc", "ntsvcs", "svcctl", "remcom")):
        return None

    return Alert(
        rule="pipe_connection",
        technique="T1021.002",
        severity="high",
        summary=f"Remote service pipe connected: {pipe}",
        event=event,
    )


def run_detectors(events: Iterable[Event]) -> list[Alert]:
    """Apply every rule to every event."""
    alerts: list[Alert] = []
    for event in events:
        for detector in RULES:
            alert = detector(event)
            if alert is not None:
                alerts.append(alert)
    return alerts
