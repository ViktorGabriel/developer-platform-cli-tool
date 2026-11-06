"""Pydantic v2 models representing security findings and audit summaries."""

from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting findings from highest to lowest severity."""
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)


class RuleCategory(StrEnum):
    """Categorization of audit rules."""

    DOCKERFILE = "DOCKERFILE"
    CONTAINER = "CONTAINER"
    SECRETS = "SECRETS"
    CONFIG = "CONFIG"


class Finding(BaseModel):
    """Individual security finding or policy violation."""

    rule_id: str = Field(..., description="Unique rule code, e.g. SEC-DKR-001")
    title: str = Field(..., description="Short summary of the violation")
    description: str = Field(..., description="Detailed description of the risk")
    severity: Severity = Field(..., description="Severity level")
    category: RuleCategory = Field(..., description="Audit rule category")
    target: str = Field(..., description="Audited target (file path, container name, etc.)")
    line_number: int | None = Field(None, description="Line number where issue was found")
    snippet: str | None = Field(None, description="Code or config snippet triggering finding")
    remediation: str = Field(..., description="Recommended fix or hardening action")


class AuditSummary(BaseModel):
    """Aggregated metrics for an audit run."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    targets_scanned: int = 0
    scan_duration_seconds: float = 0.0

    @classmethod
    def from_findings(
        cls,
        findings: list[Finding],
        targets_scanned: int,
        duration: float,
    ) -> "AuditSummary":
        """Build summary metrics from a list of findings."""
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return cls(
            total_findings=len(findings),
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
            targets_scanned=targets_scanned,
            scan_duration_seconds=round(duration, 3),
        )
