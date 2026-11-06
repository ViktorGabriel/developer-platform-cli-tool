"""Pydantic v2 model representing an entire audit report."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from cloudsec.models.finding import AuditSummary, Finding


class AuditReport(BaseModel):
    """Complete security audit report produced by CloudSec."""

    tool_name: str = Field(default="CloudSec CLI", description="Audit tool identifier")
    version: str = Field(default="0.1.0", description="Tool version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Audit execution timestamp in UTC",
    )
    summary: AuditSummary = Field(..., description="Metrics summary")
    findings: list[Finding] = Field(default_factory=list, description="List of detected findings")

    def has_critical_or_high(self) -> bool:
        """Returns True if any CRITICAL or HIGH findings were detected."""
        return self.summary.critical > 0 or self.summary.high > 0
