"""Tests for container parser and container security scanner."""

from cloudsec.models.finding import Severity
from cloudsec.parsers.container import ContainerInfo, ContainerParser
from cloudsec.scanners.container_rules import ContainerScanner


def test_scan_vulnerable_container() -> None:
    vulnerable_container = ContainerInfo(
        id="c1234567890a",
        name="web-service-vuln",
        image="ubuntu:latest",
        status="running",
        user="root",
        privileged=True,
        exposed_ports=["22/tcp", "3306/tcp"],
        port_bindings={
            "22/tcp": [{"HostIp": "0.0.0.0", "HostPort": "2222"}],
            "3306/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3306"}],
        },
        env_vars=["PASSWORD=supersecret_pass", "ENV=prod"],
    )

    findings = ContainerScanner.scan_container(vulnerable_container)
    rule_ids = {f.rule_id for f in findings}

    assert "SEC-CTR-001" in rule_ids  # Root user
    assert "SEC-CTR-002" in rule_ids  # Privileged mode
    assert "SEC-CTR-003" in rule_ids  # Exposed sensitive ports
    assert "SEC-CTR-004" in rule_ids  # Env var secret

    privileged_finding = next(f for f in findings if f.rule_id == "SEC-CTR-002")
    assert privileged_finding.severity == Severity.CRITICAL


def test_scan_secure_container() -> None:
    secure_container = ContainerInfo(
        id="c9876543210b",
        name="api-gateway-secure",
        image="myrepo/api:1.4.2",
        status="running",
        user="10001:10001",
        privileged=False,
        exposed_ports=["8080/tcp"],
        port_bindings={"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]},
        env_vars=["ENVIRONMENT=production", "LOG_LEVEL=info"],
    )

    findings = ContainerScanner.scan_container(secure_container)
    critical_or_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_or_high) == 0


def test_container_parser_daemon_unreachable() -> None:
    # A dummy parser trying to connect to non-existent daemon
    parser = ContainerParser(client=None)
    # If Docker daemon is not running or socket invalid, it raises RuntimeError with explanation
    try:
        parser.get_client()
    except RuntimeError as err:
        assert "Docker daemon" in str(err)
