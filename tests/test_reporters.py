"""Tests for audit report generators (Terminal, JSON, Markdown)."""

import json
from io import StringIO

from rich.console import Console

from cloudsec.models.finding import AuditSummary, Finding, RuleCategory, Severity
from cloudsec.models.report import AuditReport
from cloudsec.reporters.json_reporter import JsonReporter
from cloudsec.reporters.markdown_reporter import MarkdownReporter
from cloudsec.reporters.sarif_reporter import SarifReporter
from cloudsec.reporters.terminal_reporter import TerminalReporter


def sample_report() -> AuditReport:
    findings = [
        Finding(
            rule_id="SEC-DKR-001",
            title="Root user execution",
            description="Container runs as root",
            severity=Severity.HIGH,
            category=RuleCategory.DOCKERFILE,
            target="Dockerfile",
            line_number=1,
            snippet="FROM ubuntu",
            remediation="Add USER 10001",
        ),
        Finding(
            rule_id="SEC-SEC-001",
            title="Private key leaked",
            description="RSA private key found",
            severity=Severity.CRITICAL,
            category=RuleCategory.SECRETS,
            target="config.yaml",
            line_number=10,
            snippet="private_key: [REDACTED]",
            remediation="Use Vault",
        ),
    ]
    summary = AuditSummary.from_findings(findings, targets_scanned=2, duration=0.45)
    return AuditReport(summary=summary, findings=findings)


def test_json_reporter() -> None:
    report = sample_report()
    rendered = JsonReporter.render(report)
    parsed = json.loads(rendered)

    assert parsed["tool_name"] == "CloudSec CLI"
    assert parsed["summary"]["total_findings"] == 2
    assert parsed["summary"]["critical"] == 1
    assert parsed["summary"]["high"] == 1
    assert len(parsed["findings"]) == 2


def test_markdown_reporter() -> None:
    report = sample_report()
    md = MarkdownReporter.render(report)

    assert "# 🛡️ Relatório de Auditoria de Segurança" in md
    assert "CRITICAL" in md
    assert "SEC-DKR-001" in md
    assert "SEC-SEC-001" in md
    assert "STATUS: FALHA" in md


def test_markdown_reporter_clean() -> None:
    clean_summary = AuditSummary.from_findings([], targets_scanned=1, duration=0.1)
    clean_report = AuditReport(summary=clean_summary, findings=[])
    md = MarkdownReporter.render(clean_report)

    assert "STATUS: SUCESSO" in md
    assert "Nenhum apontamento de segurança" in md


def test_terminal_reporter() -> None:
    report = sample_report()
    string_io = StringIO()
    console = Console(file=string_io, force_terminal=False, color_system=None)
    reporter = TerminalReporter(console=console)
    reporter.print_report(report)

    output = string_io.getvalue()
    assert "CloudSec & Container Audit CLI" in output
    assert "Sumário Executivo" in output
    assert "SEC-DKR-001" in output


def test_sarif_reporter() -> None:
    report = sample_report()
    sarif_str = SarifReporter.render(report)
    sarif_data = json.loads(sarif_str)

    assert sarif_data["version"] == "2.1.0"
    assert "$schema" in sarif_data
    assert len(sarif_data["runs"]) == 1

    driver = sarif_data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "CloudSec CLI"
    assert len(driver["rules"]) == 2

    results = sarif_data["runs"][0]["results"]
    assert len(results) == 2

    # Check level mappings
    levels = {r["level"] for r in results}
    assert "error" in levels

    # Verify physical locations
    for res in results:
        loc = res["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert loc["region"]["startLine"] in (1, 10)
