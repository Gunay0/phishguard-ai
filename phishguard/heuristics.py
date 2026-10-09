"""Deterministic text heuristics (English + Azerbaijani). No AI, no network."""

from __future__ import annotations

import re

from phishguard.models import Language, RiskLevel

# Azerbaijani letters are folded to ASCII so "sifre" and "\u015fifr\u0259" match.
# Each mapping is 1 char -> 1 char, so positions stay identical to the original.
_FOLD = str.maketrans({
    "\u0259": "e", "\u018f": "e",
    "\u0131": "i", "\u0130": "i",
    "\u00f6": "o", "\u00d6": "o",
    "\u00fc": "u", "\u00dc": "u",
    "\u015f": "s", "\u015e": "s",
    "\u00e7": "c", "\u00c7": "c",
    "\u011f": "g", "\u011e": "g",
})


def fold(text: str) -> str:
    """Lowercase and ASCII-fold Azerbaijani letters, preserving length."""
    folded = text.translate(_FOLD).lower()
    if len(folded) == len(text):
        return folded
    return "".join(c.translate(_FOLD).lower()[:1] or c for c in text)

_AZ_WORDS = re.compile(
    r"\b(ve|ucun|hesab|sifre|kod|odenis|bank|kart|tecili|mubarek|"
    r"qazandiniz|link|daxil|olun|bloklanib|yoxlayin|musteri|zeng)\b"
)
_EN_WORDS = re.compile(
    r"\b(the|your|account|password|verify|urgent|click|please|payment|"
    r"bank|suspended|dear|login|confirm|within|hours)\b"
)
_AZ_ONLY_CHARS = set("\u0259\u018f\u0131\u0130\u015f\u015e\u011f\u011e")


def detect_language(text: str) -> Language:
    """Best-effort language guess. Never claims certainty."""
    folded = fold(text)
    az_score = len(_AZ_WORDS.findall(folded))
    en_score = len(_EN_WORDS.findall(folded))
    az_score += 2 * sum(1 for c in text if c in _AZ_ONLY_CHARS)
    if az_score == 0 and en_score == 0:
        return Language.UNKNOWN
    if az_score >= 2 and en_score >= 2:
        return Language.MIXED
    return Language.AZERBAIJANI if az_score > en_score else Language.ENGLISH

from dataclasses import dataclass

from phishguard.models import Category, Indicator


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: Category
    title: str
    explanation: str
    weight: int
    patterns: tuple[str, ...]  # regexes run on fold(text)


RULES: list[Rule] = [
    Rule(
        "urgency_deadline", Category.URGENCY,
        "Deadline pressure",
        "Scammers create time pressure so you act before thinking.",
        4,
        (r"\bwithin \d+ (hours?|minutes?)\b", r"\bimmediately\b",
         r"\burgent(ly)?\b", r"\bact now\b", r"\blast warning\b",
         r"\btecili\b", r"\bderhal\b", r"\bson xeb[ae]rdarliq\b",
         r"\b\d+ saat (erzinde|icinde)\b"),
    ),
    Rule(
        "credential_request", Category.CREDENTIAL_THEFT,
        "Asks for password, PIN or one-time code",
        "Legitimate organizations never ask for your password, PIN or OTP.",
        9,
(r"\b(send|share|enter|provide|confirm) (us |me )?(your )?"
         r"(password|pin|otp|cvv|verification code)\b",
         r"\b(sifre|parol|pin|cvv|otp)\w* (daxil|gonder|bildir|paylas)",
         r"\b(daxil edin|gonderin|bildirin) .{0,25}\b(sifre|parol|kod|pin|cvv)\b"),
    ),
    Rule(
        "payment_request", Category.PAYMENT_FRAUD,
        "Unusual payment request",
        "Requests for gift cards, crypto or wire transfers are classic fraud.",
        8,
        (r"\bgift cards?\b", r"\b(bitcoin|crypto|usdt)\b",
         r"\bwire transfer\b", r"\bpay (a |the )?(fee|fine|deposit)\b",
         r"\bhediyye kart", r"\b(kocur|gonder)\w* (pul|vesait)\b"),
    ),
    Rule(
        "impersonation_claim", Category.IMPERSONATION,
        "Claims to be a bank, support team or authority",
        "Scammers pose as trusted organizations. Verify via official channels.",
        5,
        (r"\b(this is|we are|from) (the )?(your )?(bank|security team|"
         r"support team|tax office|police)\b",
         r"\b(bank|musteri xidmeti|texniki destek) (adindan|terefinden)\b"),
    ),
    Rule(
        "threat_language", Category.THREAT,
        "Threatens account closure or legal action",
        "Threats are used to scare you into acting without verifying.",
        6,

        (r"\baccount (will be |has been )?(suspended|closed|blocked|locked)\b",
         r"\blegal action\b", r"\barrest\b",
         r"\bhesab\w* (bloklan|baglan|dayandir)\w*",
         r"\bmehkeme\b"),
    ),
    Rule(
        "reward_lure", Category.REWARD_LURE,
        "Prize or reward lure",
        "Unexpected prizes are a common bait to collect personal data.",
        5,
        (r"\byou (have )?(won|been selected)\b", r"\bfree (gift|prize)\b",
         r"\bqazandiniz\b", r"\bmubarek olsun\b", r"\bhediyye qazan"),
    ),
]

_MAX_EVIDENCE_PER_RULE = 3


def find_indicators(text: str) -> list[Indicator]:
    """Run all rules. Evidence is copied verbatim from the original text."""
    folded = fold(text)
    found: list[Indicator] = []
    for rule in RULES:
        snippets: list[str] = []
        for pattern in rule.patterns:
            for match in re.finditer(pattern, folded):
                snippet = text[match.start():match.end()].strip()
                if snippet and snippet not in snippets:
                    snippets.append(snippet)
        if snippets:
            found.append(Indicator(
                rule.rule_id, rule.category, rule.title,
                rule.explanation, rule.weight,
                tuple(snippets[:_MAX_EVIDENCE_PER_RULE]),
            ))
    return found

_MIN_TEXT_LENGTH = 30


def heuristic_risk(indicators: list[Indicator], text_length: int) -> RiskLevel:
    """Transparent rule-based risk level. Not a probability."""
    if not indicators:
        return RiskLevel.UNKNOWN if text_length < _MIN_TEXT_LENGTH else RiskLevel.LOW
    strongest = max(i.weight for i in indicators)
    total = sum(i.weight for i in indicators)
    if strongest >= 9 or total >= 15:
        return RiskLevel.HIGH
    if strongest >= 5 or total >= 8:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
