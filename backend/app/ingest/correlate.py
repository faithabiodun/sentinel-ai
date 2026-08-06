"""Alerts to incidents.

An alert on its own is a fact. An incident is a claim that several facts belong
to the same story, and it is the unit an analyst actually works. Correlation is
deliberately deterministic — the agent should be handed a coherent case and
spend its reasoning on what the case means, not on reassembling it.

Grouping is by host and time proximity. Two alerts on the same machine minutes
apart are almost certainly the same activity; the same alert on two machines a
year apart is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .detectors import Alert

# How long a case stays open to new alerts. Long enough to span a dwell period
# of a few minutes, short enough that unrelated activity on a busy host does not
# get swept into one giant incident.
DEFAULT_WINDOW = timedelta(minutes=30)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# ATT&CK tactic for each technique the detectors can emit. Tactic diversity is
# what separates a single odd event from an intrusion with a shape.
TACTICS: dict[str, str] = {
    "T1003.001": "credential-access",
    "T1055": "defense-evasion",
    "T1059.001": "execution",
    "T1047": "lateral-movement",
    "T1021.002": "lateral-movement",
    "T1021.006": "lateral-movement",
    "T1053.005": "persistence",
    "T1218.005": "defense-evasion",
    "T1218.010": "defense-evasion",
    "T1218.011": "defense-evasion",
    "T1218.004": "defense-evasion",
    "T1220": "defense-evasion",
}

# Reads as the headline of the case. Ordered by how much an analyst cares.
TACTIC_HEADLINE = [
    ("credential-access", "Credential access"),
    ("lateral-movement", "Lateral movement"),
    ("persistence", "Persistence established"),
    ("defense-evasion", "Defence evasion"),
    ("execution", "Suspicious execution"),
]


@dataclass
class TimelineEntry:
    seq: int
    occurred_at: datetime
    actor: str
    action: str
    technique: str
    detail: str | None = None
    occurrences: int = 1


@dataclass
class Incident:
    ref: str
    title: str
    severity: str
    host: str
    opened_at: datetime
    closed_at: datetime
    alerts: list[Alert] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    users: list[str] = field(default_factory=list)

    @property
    def techniques(self) -> list[str]:
        seen: list[str] = []
        for alert in self.alerts:
            if alert.technique not in seen:
                seen.append(alert.technique)
        return seen

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for technique in self.techniques:
            tactic = TACTICS.get(technique, "unknown")
            if tactic not in seen:
                seen.append(tactic)
        return seen

    @property
    def primary_technique(self) -> str:
        """The technique the case is filed under — the most severe one seen."""
        return max(
            self.alerts,
            key=lambda a: SEVERITY_ORDER.index(a.severity),
        ).technique


def _escalate(severity: str, steps: int = 1) -> str:
    index = min(SEVERITY_ORDER.index(severity) + steps, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[index]


def _severity_for(alerts: list[Alert], tactics: list[str]) -> str:
    base = max(alerts, key=lambda a: SEVERITY_ORDER.index(a.severity)).severity

    # Three or more distinct tactics is a chain, not a blip. An analyst treats
    # execution plus credential access plus lateral movement as worse than the
    # worst of them individually, because it implies an operator with a plan.
    if len(tactics) >= 3:
        return _escalate(base)
    return base


def _title_for(host: str, tactics: list[str], techniques: list[str]) -> str:
    short_host = host.split(".")[0]
    for tactic, headline in TACTIC_HEADLINE:
        if tactic in tactics:
            if len(tactics) >= 3:
                return f"{headline} in a multi-stage chain on {short_host}"
            return f"{headline} on {short_host}"
    return f"Suspicious activity on {short_host} ({', '.join(techniques[:2])})"


def _timeline_for(alerts: list[Alert]) -> list[TimelineEntry]:
    """Order alerts into a narrative, rolling up repeats.

    One action often lands as several events — three child processes, two
    handles on the same target. Listing each is technically faithful and
    useless to read, so consecutive entries describing the same action by the
    same actor collapse into one carrying a count.
    """
    ordered = sorted(alerts, key=lambda a: a.event.observed_at)
    entries: list[TimelineEntry] = []
    occurrences: list[int] = []

    for alert in ordered:
        event = alert.event
        actor = event.process_name or event.user or "unknown"

        if entries and entries[-1].action == alert.summary and entries[-1].actor == actor:
            occurrences[-1] += 1
            entries[-1].occurred_at = min(entries[-1].occurred_at, event.observed_at)
            continue

        entries.append(
            TimelineEntry(
                seq=0,
                occurred_at=event.observed_at,
                actor=actor,
                action=alert.summary,
                technique=alert.technique,
                detail=event.command_line,
            )
        )
        occurrences.append(1)

    for seq, (entry, count) in enumerate(zip(entries, occurrences), 1):
        entry.seq = seq
        entry.occurrences = count

    return entries


def correlate(alerts: list[Alert], window: timedelta = DEFAULT_WINDOW) -> list[Incident]:
    """Group alerts into incidents by host, then by gaps in time."""
    if not alerts:
        return []

    by_host: dict[str, list[Alert]] = {}
    for alert in alerts:
        by_host.setdefault(alert.event.host, []).append(alert)

    clusters: list[list[Alert]] = []
    for host_alerts in by_host.values():
        host_alerts.sort(key=lambda a: a.event.observed_at)
        current = [host_alerts[0]]

        for alert in host_alerts[1:]:
            gap = alert.event.observed_at - current[-1].event.observed_at
            if gap <= window:
                current.append(alert)
            else:
                clusters.append(current)
                current = [alert]
        clusters.append(current)

    clusters.sort(key=lambda c: c[0].event.observed_at)

    incidents: list[Incident] = []
    for number, cluster in enumerate(clusters, 1):
        host = cluster[0].event.host
        incident = Incident(
            ref=f"INC-{number:04d}",
            title="",
            severity="info",
            host=host,
            opened_at=cluster[0].event.observed_at,
            closed_at=cluster[-1].event.observed_at,
            alerts=cluster,
            users=sorted({a.event.user for a in cluster if a.event.user}),
        )
        incident.severity = _severity_for(cluster, incident.tactics)
        incident.title = _title_for(host, incident.tactics, incident.techniques)
        incident.timeline = _timeline_for(cluster)
        incidents.append(incident)

    # Worst first, then most recent — the order an analyst wants the queue in.
    incidents.sort(
        key=lambda i: (-SEVERITY_ORDER.index(i.severity), -i.opened_at.timestamp())
    )
    return incidents
