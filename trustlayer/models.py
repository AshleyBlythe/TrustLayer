"""Data models for TrustLayer scan findings and results."""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    OBSERVED = "observed"
    POSSIBLE = "possible"
    NEEDS_VERIFICATION = "needs_verification"


@dataclasses.dataclass
class Finding:
    check_id: str
    title: str
    severity: Severity
    confidence: Confidence
    explanation: str
    who_could_use: str
    what_they_access: str
    possible_damage: str
    likelihood: str
    fastest_fix: str
    ask_human: bool
    evidence: str
    source: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "explanation": self.explanation,
            "who_could_use": self.who_could_use,
            "what_they_access": self.what_they_access,
            "possible_damage": self.possible_damage,
            "likelihood": self.likelihood,
            "fastest_fix": self.fastest_fix,
            "ask_human": self.ask_human,
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclasses.dataclass
class ScanResult:
    target: str
    findings: List[Finding] = dataclasses.field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    scanned_urls: int = 0
    errors: List[str] = dataclasses.field(default_factory=list)
    url_scan_enabled: bool = False

    def counts_by_severity(self) -> dict:
        counts: dict = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "scanned_urls": self.scanned_urls,
            "url_scan_enabled": self.url_scan_enabled,
            "severity_counts": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
