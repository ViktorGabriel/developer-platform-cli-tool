"""Tests for Git history parser and scanner with Git mocks."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cloudsec.models.finding import Severity
from cloudsec.parsers.git import GitParser
from cloudsec.scanners.git_scanner import GitHistoryScanner

MOCK_GIT_LOG = """COMMIT_META:462f442b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f|Viktor Gabriel|Fri Nov 6 15:00:00 2026 -0300|feat: add cloud service configuration
diff --git a/services/aws.py b/services/aws.py
index 0000000..1111111 100644
--- /dev/null
+++ b/services/aws.py
@@ -0,0 +1,5 @@
+# Configuration service
+AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
+port = 8080
+password = "admin123"
+# End of config
COMMIT_META:1111222233334444555566667777888899990000|Dev Engineer|Thu Nov 5 12:00:00 2026 -0300|fix: add secure routes
diff --git a/routes/api.py b/routes/api.py
index 1111111..2222222 100644
--- a/routes/api.py
+++ b/routes/api.py
@@ -10,2 +10,3 @@
 def health_check():
+    return {"status": "ok"}
"""


def test_parse_git_log_output() -> None:
    diffs = GitParser.parse_git_log_output(MOCK_GIT_LOG)
    assert len(diffs) > 0

    # Verify commit metadata parsing
    aws_diff = next(d for d in diffs if "AKIAIOSFODNN7EXAMPLE" in d.added_content)
    assert aws_diff.commit_hash.startswith("462f442")
    assert aws_diff.author == "Viktor Gabriel"
    assert aws_diff.file_path == "services/aws.py"
    assert aws_diff.line_number == 2
    assert "AKIAIOSFODNN7EXAMPLE" in aws_diff.added_content


def test_git_history_scanner_detects_secrets() -> None:
    diffs = GitParser.parse_git_log_output(MOCK_GIT_LOG)
    findings = GitHistoryScanner.scan_diffs(diffs)

    rule_ids = {f.rule_id for f in findings}
    assert "SEC-SEC-002" in rule_ids  # AWS Key
    assert "SEC-SEC-006" in rule_ids  # password: admin123

    # Check target representation
    aws_finding = next(f for f in findings if f.rule_id == "SEC-SEC-002")
    assert "462f442b:services/aws.py" in aws_finding.target
    assert aws_finding.severity == Severity.CRITICAL
    assert aws_finding.line_number == 2


@patch("subprocess.run")
def test_git_parser_subprocess_mock(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(stdout=MOCK_GIT_LOG, returncode=0)

    diffs = GitParser.get_commit_diffs(repo_path=Path("."), max_commits=5)
    assert len(diffs) > 0
    mock_run.assert_called_once()
    args = mock_run.call_args[0][0]
    assert "git" in args
    assert "-n5" in args


@patch("subprocess.run")
def test_git_parser_failure(mock_run: MagicMock, tmp_path: Path) -> None:
    repo = tmp_path / "mock_repo"
    (repo / ".git").mkdir(parents=True)
    mock_run.side_effect = subprocess.CalledProcessError(returncode=128, cmd="git log")

    with pytest.raises(RuntimeError) as exc_info:
        GitParser.get_commit_diffs(repo_path=repo)

    assert "Falha ao executar comando Git" in str(exc_info.value)


def test_git_scanner_real_repo() -> None:
    # Scan the actual repository commit
    findings = GitHistoryScanner.scan_repository(repo_path=Path("."), max_commits=1)
    # The scan executes without exceptions
    assert isinstance(findings, list)
