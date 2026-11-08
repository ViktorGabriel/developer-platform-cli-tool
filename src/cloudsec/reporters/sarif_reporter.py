"""SARIF (Static Analysis Results Interchange Format) v2.1.0 reporter for GitHub Security."""

import json
import os
import re
from typing import Any

from cloudsec.models.finding import Severity
from cloudsec.models.report import AuditReport

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"


def severity_to_sarif_level(severity: Severity) -> str:
    """Map CloudSec severity to SARIF standard level: error, warning, note."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


class SarifReporter:
    """Serializes AuditReport into OASIS SARIF 2.1.0 format for GitHub Code Scanning."""

    @classmethod
    def to_dict(cls, report: AuditReport) -> dict[str, Any]:
        """Convert an AuditReport into SARIF dictionary structure."""
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in report.findings:
            sarif_level = severity_to_sarif_level(finding.severity)

            # Register rule if not already present in driver rules
            if finding.rule_id not in rules_map:
                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.rule_id.replace("-", "_"),
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "help": {
                        "text": f"{finding.description}\n\nRemediação recomendada: {finding.remediation}"
                    },
                    "defaultConfiguration": {"level": sarif_level},
                    "properties": {
                        "category": finding.category.value,
                        "severity": finding.severity.value,
                    },
                }

            # Normalize URI / target path for SARIF (relative forward slashes for %SRCROOT%)
            target_uri = finding.target.replace("\\", "/")
            if not target_uri.startswith("http"):
                try:
                    cwd = os.getcwd().replace("\\", "/")
                    if target_uri.startswith(cwd + "/"):
                        target_uri = target_uri[len(cwd) + 1 :]
                except OSError:
                    pass
                # Strip Windows drive letter (e.g. C:/ or D:/) so SARIF doesn't treat drive as URI scheme
                target_uri = re.sub(r"^[A-Za-z]:/+", "", target_uri)
                target_uri = target_uri.lstrip("/")

            location_dict: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_uri or "unknown",
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }

            if finding.line_number is not None and finding.line_number > 0:
                location_dict["physicalLocation"]["region"] = {
                    "startLine": finding.line_number,
                }
                if finding.snippet:
                    location_dict["physicalLocation"]["region"]["snippet"] = {
                        "text": finding.snippet
                    }

            result_entry: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": sarif_level,
                "message": {
                    "text": f"{finding.title}: {finding.description} (Remediação: {finding.remediation})"
                },
                "locations": [location_dict],
            }
            results.append(result_entry)

        sarif_doc = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": report.tool_name,
                            "semanticVersion": report.version,
                            "informationUri": "https://github.com/ViktorGabriel/developer-platform-cli-tool",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return sarif_doc

    @classmethod
    def render(cls, report: AuditReport) -> str:
        """Render AuditReport into indented SARIF JSON string."""
        data = cls.to_dict(report)
        return json.dumps(data, indent=2, ensure_ascii=False)
