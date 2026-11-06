"""JSON reporter for CloudSec audit results."""

from cloudsec.models.report import AuditReport


class JsonReporter:
    """Serializes AuditReport to standardized formatted JSON."""

    @staticmethod
    def render(report: AuditReport) -> str:
        """Return formatted JSON string."""
        return report.model_dump_json(indent=2)
