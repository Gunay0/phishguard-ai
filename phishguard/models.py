"""Shared data models for PhishGuard AI.

Deterministic findings (Indicator, UrlFinding) and AI output (AIAssessment)
are separate types so they can never be mixed up in the UI.
AnalysisResult deliberately does NOT store the analyzed message text,
only its length, to respect the "do not store messages" privacy rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class RiskLevel(str, Enum):
    """Overall risk categories. UNKNOWN means evidence is insufficient."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    UNKNOWN = "Unknown"


# UNKNOWN ranks lowest: it carries no evidence and never outranks a finding.
RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.UNKNOWN: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
}


def max_risk(a: RiskLevel, b: RiskLevel) -> RiskLevel:
    """Return the more severe of two risk levels."""
    return a if RISK_RANK[a] >= RISK_RANK[b] else b

class Category(str, Enum):
    """Categories of deterministic text indicators."""

    URGENCY = "Urgency and pressure"
    CREDENTIAL_THEFT = "Credential or code request"
    PAYMENT_FRAUD = "Payment fraud"
    IMPERSONATION = "Impersonation"
    THREAT = "Threats and intimidation"
    REWARD_LURE = "Prize or reward lure"


class Language(str, Enum):
    """Detected message language (best effort, heuristic)."""

    ENGLISH = "English"
    AZERBAIJANI = "Azerbaijani"
    MIXED = "Mixed"
    UNKNOWN = "Unknown"


class AIStatus(str, Enum):
    """What happened with the optional AI analysis."""

    NOT_REQUESTED = "not_requested"
    USED = "used"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    REJECTED = "rejected"

@dataclass(frozen=True)
class Indicator:
    """A deterministic text indicator found by a rule (not AI-generated)."""

    rule_id: str
    category: Category
    title: str
    explanation: str
    weight: int  # 1 (weak signal) .. 10 (strong signal)
    evidence: tuple[str, ...] = ()  # literal snippets from the message

    def __post_init__(self) -> None:
        if not 1 <= self.weight <= 10:
            raise ValueError(f"weight must be 1..10, got {self.weight}")


@dataclass(frozen=True)
class UrlFlag:
    """A single suspicious property of a URL (deterministic)."""

    flag_id: str
    title: str
    explanation: str
    weight: int  # 1 .. 10

    def __post_init__(self) -> None:
        if not 1 <= self.weight <= 10:
            raise ValueError(f"weight must be 1..10, got {self.weight}")


@dataclass(frozen=True)
class UrlFinding:
    """Result of inspecting one URL as text. The URL is never visited."""

    url: str       # exactly as found in the message
    defanged: str  # safe display form, e.g. hxxps://example[.]com
    host: str      # parsed host, may be empty if parsing failed
    flags: tuple[UrlFlag, ...] = ()

    @property
    def total_weight(self) -> int:
        return sum(flag.weight for flag in self.flags)

@dataclass(frozen=True)
class AIEvidence:
    """A quote the AI says supports its assessment.

    Only quotes verified to appear verbatim in the message are kept.
    """

    quote: str
    why: str


@dataclass(frozen=True)
class AIAssessment:
    """Validated output of the AI model. Always shown as AI-generated."""

    risk_level: RiskLevel
    summary: str
    reasons: tuple[str, ...] = ()
    evidence: tuple[AIEvidence, ...] = ()
    recommendations: tuple[str, ...] = ()
    model_name: str = ""
    dropped_evidence_count: int = 0  # quotes removed: not found in text

@dataclass
class AnalysisResult:
    """Everything the UI needs to display. Contains no message text."""

    input_length: int
    language: Language
    indicators: list[Indicator] = field(default_factory=list)
    url_findings: list[UrlFinding] = field(default_factory=list)
    heuristic_risk: RiskLevel = RiskLevel.UNKNOWN
    final_risk: RiskLevel = RiskLevel.UNKNOWN
    reasons: list[str] = field(default_factory=list)
    ai_status: AIStatus = AIStatus.NOT_REQUESTED
    ai_message: str = ""  # user-facing note about the AI step
    ai_assessment: AIAssessment | None = None
    limitations: list[str] = field(default_factory=list)
