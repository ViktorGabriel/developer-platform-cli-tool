"""Integration tests for Typer CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from cloudsec.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CloudSec & Container Audit CLI" in result.stdout
    assert "0.1.0" in result.stdout


def test_cli_scan_dockerfile_vulnerable(vulnerable_dockerfile: Path) -> None:
    result = runner.invoke(
        app, ["scan-dockerfile", str(vulnerable_dockerfile), "--format", "table"]
    )
    assert result.exit_code == 0
    assert "SEC-DKR-001" in result.stdout
    assert "FALHA" in result.stdout


def test_cli_scan_dockerfile_json(vulnerable_dockerfile: Path) -> None:
    result = runner.invoke(app, ["scan-dockerfile", str(vulnerable_dockerfile), "--format", "json"])
    assert result.exit_code == 0
    assert '"tool_name": "CloudSec CLI"' in result.stdout
    assert '"rule_id": "SEC-DKR-001"' in result.stdout


def test_cli_scan_dockerfile_markdown(vulnerable_dockerfile: Path) -> None:
    result = runner.invoke(
        app, ["scan-dockerfile", str(vulnerable_dockerfile), "--format", "markdown"]
    )
    assert result.exit_code == 0
    assert "# 🛡️ Relatório de Auditoria de Segurança" in result.stdout


def test_cli_scan_dockerfile_fail_on_critical(vulnerable_dockerfile: Path) -> None:
    result = runner.invoke(
        app,
        ["scan-dockerfile", str(vulnerable_dockerfile), "--fail-on-critical"],
    )
    assert result.exit_code == 1
    assert "Falha na auditoria" in result.stdout


def test_cli_scan_config_vulnerable(vulnerable_config_yaml: Path) -> None:
    result = runner.invoke(app, ["scan-config", str(vulnerable_config_yaml)])
    assert result.exit_code == 0
    assert "SEC-SEC-002" in result.stdout


def test_cli_scan_config_save_file(vulnerable_config_json: Path, tmp_path: Path) -> None:
    out_file = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["scan-config", str(vulnerable_config_json), "--format", "json", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "SEC-SEC-003" in content


def test_cli_scan_all(
    tmp_path: Path, vulnerable_dockerfile: Path, secure_config_yaml: Path
) -> None:
    # Copy files into a temporary directory
    target_dir = tmp_path / "project"
    target_dir.mkdir()
    (target_dir / "Dockerfile").write_text(
        vulnerable_dockerfile.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (target_dir / "config.yaml").write_text(
        secure_config_yaml.read_text(encoding="utf-8"), encoding="utf-8"
    )

    result = runner.invoke(app, ["scan-all", str(target_dir), "--format", "table"])
    assert result.exit_code == 0
    assert "SEC-DKR-001" in result.stdout


def test_cli_scan_dockerfile_sarif(vulnerable_dockerfile: Path) -> None:
    result = runner.invoke(
        app,
        ["scan-dockerfile", str(vulnerable_dockerfile), "--format", "sarif"],
    )
    assert result.exit_code == 0
    assert '"version": "2.1.0"' in result.stdout
    assert '"ruleId": "SEC-DKR-001"' in result.stdout


def test_cli_scan_git_history() -> None:
    result = runner.invoke(app, ["scan-git-history", ".", "--commits", "1", "--format", "table"])
    assert result.exit_code == 0
    assert "CloudSec & Container Audit CLI" in result.stdout


def test_cli_scan_git_history_sarif_file(tmp_path: Path) -> None:
    out_file = tmp_path / "git_audit.sarif"
    result = runner.invoke(
        app,
        ["scan-git-history", ".", "--commits", "1", "--format", "sarif", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert '"version": "2.1.0"' in content


def test_cli_scan_git_history_invalid_repo(tmp_path: Path) -> None:
    empty_dir = tmp_path / "not_a_repo"
    empty_dir.mkdir()
    result = runner.invoke(app, ["scan-git-history", str(empty_dir)])
    assert result.exit_code == 2
    assert "Erro ao inspecionar histórico Git" in result.stdout
