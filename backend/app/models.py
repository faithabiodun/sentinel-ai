"""Pydantic models for API request/response bodies."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, field_validator


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    display_name: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v

    @field_validator("display_name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Display name cannot be empty")
        return v.strip()


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    analyst_id: str
    email: str
    display_name: str
    role: str


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

class HypothesisOut(BaseModel):
    id: str
    statement: str
    status: str
    confidence: float | None
    supporting: int
    contradicting: int
    note: str | None
    created_at: str
    resolved_at: str | None


class EvidenceOut(BaseModel):
    id: str
    claim: str
    supports: bool
    source_tool: str | None
    created_at: str


class TimelineEventOut(BaseModel):
    seq: int
    occurred_at: str
    actor: str | None
    action: str
    attack_technique: str | None


class EntityOut(BaseModel):
    id: str
    kind: str
    value: str
    verdict: str
    reasoning: str | None
    risk_score: int | None
    times_seen: int
    first_seen: str
    cleared_count: int


class SimilarIncident(BaseModel):
    ref: str
    title: str
    similarity: float


class IncidentSummary(BaseModel):
    id: str
    ref: str
    title: str
    severity: str
    status: str
    host: str | None
    primary_user: str | None
    attack_technique: str | None
    alert_count: int
    opened_at: str
    summary: str | None


class IncidentDetail(BaseModel):
    id: str
    ref: str
    title: str
    severity: str
    status: str
    host: str | None
    primary_user: str | None
    summary: str | None
    root_cause: str | None
    report: str | None
    attack_technique: str | None
    opened_at: str
    closed_at: str | None
    alert_count: int
    hypotheses: list[HypothesisOut]
    timeline: list[TimelineEventOut]
    entities: list[EntityOut]
    evidence: list[EvidenceOut]
    similar: SimilarIncident | None


class QueueStats(BaseModel):
    open: int
    investigating: int
    closed: int
    auto_cleared: int
    total_alerts: int
    total_events: int
