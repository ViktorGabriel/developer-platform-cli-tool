"""Tests for Dockerfile parsing and security scanner rules."""

from pathlib import Path

from cloudsec.models.finding import Severity
from cloudsec.parsers.dockerfile import DockerfileParser
from cloudsec.scanners.dockerfile_rules import DockerfileScanner


def test_dockerfile_parser_multiline() -> None:
    content = """
    # Comment line
    RUN apt-get update && \\
        apt-get install -y curl \\
        git
    USER 10001
    """
    instructions = DockerfileParser.parse_text(content)
    assert len(instructions) == 2
    assert instructions[0].instruction == "RUN"
    assert "git" in instructions[0].arguments
    assert instructions[0].line_number == 3
    assert instructions[1].instruction == "USER"
    assert instructions[1].arguments == "10001"


def test_scan_vulnerable_dockerfile(vulnerable_dockerfile: Path) -> None:
    findings = DockerfileScanner.scan_file(vulnerable_dockerfile)

    rule_ids = {f.rule_id for f in findings}
    assert "SEC-DKR-001" in rule_ids  # Root user
    assert "SEC-DKR-002" in rule_ids  # Port 22 and 3306
    assert "SEC-DKR-003" in rule_ids  # python:latest
    assert "SEC-DKR-004" in rule_ids  # curl | bash
    assert "SEC-DKR-006" in rule_ids  # DB_PASSWORD in ENV

    # Verify high or critical findings exist
    severities = {f.severity for f in findings}
    assert Severity.CRITICAL in severities
    assert Severity.HIGH in severities


def test_scan_secure_dockerfile(secure_dockerfile: Path) -> None:
    findings = DockerfileScanner.scan_file(secure_dockerfile)
    critical_or_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_or_high) == 0


def test_explicit_root_user() -> None:
    content = """
    FROM python:3.12-slim
    USER root
    """
    instructions = DockerfileParser.parse_text(content)
    findings = DockerfileScanner.scan_instructions(instructions)

    root_findings = [f for f in findings if f.rule_id == "SEC-DKR-001"]
    assert len(root_findings) == 1
    assert "explicitamente" in root_findings[0].title


def test_empty_dockerfile() -> None:
    instructions = DockerfileParser.parse_text("")
    findings = DockerfileScanner.scan_instructions(instructions)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-DKR-001"  # No USER directive
