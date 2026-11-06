"""Scanner for inspecting Git commit history diffs for leaked credentials and secrets."""

from pathlib import Path

from cloudsec.models.finding import Finding, RuleCategory, Severity
from cloudsec.parsers.git import GitCommitDiff, GitParser
from cloudsec.scanners.secrets_rules import (
    MOCK_VAL_PATTERNS,
    PATTERNS,
    SENSITIVE_KEY_NAMES,
    SecretsScanner,
    calculate_shannon_entropy,
)


class GitHistoryScanner:
    """Scans Git commit logs and diffs for secrets introduced across commits."""

    @classmethod
    def scan_repository(cls, repo_path: Path, max_commits: int = 10) -> list[Finding]:
        """Fetch git commit diffs from repo and audit added content."""
        diffs = GitParser.get_commit_diffs(repo_path=repo_path, max_commits=max_commits)
        return cls.scan_diffs(diffs)

    @classmethod
    def scan_diffs(cls, diffs: list[GitCommitDiff]) -> list[Finding]:
        """Audit list of GitCommitDiff entries."""
        findings: list[Finding] = []

        for diff in diffs:
            line_text = diff.added_content.strip()
            target_str = (
                f"{diff.commit_hash[:8]}:{diff.file_path}" if diff.commit_hash else diff.file_path
            )

            # 1. Regex high confidence patterns
            matched = False
            for rule_id, title, pattern, severity, remediation in PATTERNS:
                if pattern.search(line_text):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=f"Git Commit: {title}",
                            description=(
                                f"Segredo introduzido no commit '{diff.commit_hash[:8]}' "
                                f"por '{diff.author}' ('{diff.message}'): padrão detectado."
                            ),
                            severity=severity,
                            category=RuleCategory.SECRETS,
                            target=target_str,
                            line_number=diff.line_number,
                            snippet=SecretsScanner._mask_secret(line_text),
                            remediation=(
                                f"{remediation} Considere usar 'git-filter-repo' ou BFG Repo-Cleaner "
                                "para purgar este commit do histórico."
                            ),
                        )
                    )
                    matched = True
                    break

            if matched:
                continue

            # 2. Key names and mock passwords
            if SENSITIVE_KEY_NAMES.search(line_text):
                # Try to extract value part
                val_candidate = line_text.split(":")[-1].split("=")[-1].strip(" '\"")
                if val_candidate:
                    is_mock = bool(MOCK_VAL_PATTERNS.match(val_candidate))
                    sev = Severity.HIGH if not is_mock else Severity.MEDIUM
                    title = (
                        "Git Commit: Senha mockada ou padrão adicionada ao histórico"
                        if is_mock
                        else "Git Commit: Credencial sensível adicionada ao histórico"
                    )
                    findings.append(
                        Finding(
                            rule_id="SEC-SEC-006",
                            title=title,
                            description=(
                                f"Commit '{diff.commit_hash[:8]}' introduziu uma credencial/senha "
                                f"no arquivo '{diff.file_path}'."
                            ),
                            severity=sev,
                            category=RuleCategory.SECRETS,
                            target=target_str,
                            line_number=diff.line_number,
                            snippet=SecretsScanner._mask_secret(line_text),
                            remediation=(
                                "Remova o segredo do commit e expurgue do histórico se já foi enviado ao remoto."
                            ),
                        )
                    )

            # 3. High entropy token strings
            elif len(line_text) >= 28 and " " not in line_text:
                entropy = calculate_shannon_entropy(line_text)
                if entropy > 4.5:
                    findings.append(
                        Finding(
                            rule_id="SEC-SEC-007",
                            title="Git Commit: Linha com alta entropia no histórico",
                            description=(
                                f"Linha adicionada no commit '{diff.commit_hash[:8]}' possui entropia de {entropy:.2f}."
                            ),
                            severity=Severity.HIGH,
                            category=RuleCategory.SECRETS,
                            target=target_str,
                            line_number=diff.line_number,
                            snippet=SecretsScanner._mask_secret(line_text),
                            remediation="Verifique se esta sequência é uma chave secreta e expurgue do histórico.",
                        )
                    )

        return findings
