"""Tests for configuration parsing and secrets scanner."""

from pathlib import Path

from cloudsec.models.finding import Severity
from cloudsec.parsers.config import ConfigParser
from cloudsec.scanners.secrets_rules import SecretsScanner, calculate_shannon_entropy


def test_shannon_entropy() -> None:
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaa") == 0.0
    # Random key has high entropy
    high_rand = "x9K@1pZ#98mN!qW$01vB&x"
    assert calculate_shannon_entropy(high_rand) > 3.5


def test_scan_vulnerable_yaml(vulnerable_config_yaml: Path) -> None:
    findings = SecretsScanner.scan_file(vulnerable_config_yaml)
    rule_ids = {f.rule_id for f in findings}

    assert "SEC-SEC-002" in rule_ids  # AWS Key
    assert "SEC-SEC-004" in rule_ids  # Database URI with password
    assert "SEC-SEC-005" in rule_ids  # JWT
    assert "SEC-SEC-006" in rule_ids  # password: changeme

    # Verify secret masking
    for f in findings:
        if f.snippet:
            assert "[REDACTED]" in f.snippet or "***" in f.snippet


def test_scan_vulnerable_json(vulnerable_config_json: Path) -> None:
    findings = SecretsScanner.scan_file(vulnerable_config_json)
    rule_ids = {f.rule_id for f in findings}

    assert "SEC-SEC-003" in rule_ids  # GitHub Token
    assert "SEC-SEC-006" in rule_ids  # admin123 secret


def test_scan_secure_config(secure_config_yaml: Path) -> None:
    findings = SecretsScanner.scan_file(secure_config_yaml)
    assert len(findings) == 0


def test_invalid_syntax(tmp_path: Path) -> None:
    bad_yaml = tmp_path / "broken.yaml"
    bad_yaml.write_text("key: [unterminated list", encoding="utf-8")

    findings = SecretsScanner.scan_file(bad_yaml)
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-CFG-ERR"


def test_private_key_detection() -> None:
    dummy_key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1+MockDataFakeKey123456789\n"
        "-----END RSA PRIVATE KEY-----"
    )
    indented_key = "\n".join(f"  {line}" for line in dummy_key.splitlines())
    _, entries = ConfigParser.parse_text(f"private_key: |\n{indented_key}", suffix=".yaml")
    findings = SecretsScanner.scan_entries(entries, target="test.yaml")

    rsa_findings = [f for f in findings if f.rule_id == "SEC-SEC-001"]
    assert len(rsa_findings) == 1
    assert rsa_findings[0].severity == Severity.CRITICAL
