"""Inspection rules for configuration files (YAML/JSON) and secrets detection."""

import math
import re
from pathlib import Path

from cloudsec.models.finding import Finding, RuleCategory, Severity
from cloudsec.parsers.config import ConfigEntry, ConfigParser

# Regex patterns for high confidence secrets
PATTERNS: list[tuple[str, str, re.Pattern[str], Severity, str]] = [
    (
        "SEC-SEC-001",
        "Chave privada embutida (Private Key)",
        re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Remova imediatamente a chave privada do arquivo de configuração e utilize um Vault ou KMS.",
    ),
    (
        "SEC-SEC-002",
        "AWS Access Key ID detectada",
        re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "Invalide a chave no AWS IAM e configure papéis IAM (IAM Roles) ou AWS Secrets Manager.",
    ),
    (
        "SEC-SEC-003",
        "GitHub Personal Access Token detectado",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
        Severity.CRITICAL,
        "Revogue imediatamente o token no GitHub e utilize variáveis de ambiente ou GitHub Actions Secrets.",
    ),
    (
        "SEC-SEC-004",
        "URI de banco de dados com credenciais em texto claro",
        re.compile(r"(?i)(postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^\s:@]+:[^\s:@]+@"),
        Severity.HIGH,
        "Não armazene senhas na string de conexão em arquivos de configuração; injete via variáveis em runtime.",
    ),
    (
        "SEC-SEC-005",
        "JSON Web Token (JWT) exposto",
        re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b"),
        Severity.HIGH,
        "Tokens JWT são efêmeros e nunca devem ser versionados em arquivos de configuração.",
    ),
]

SENSITIVE_KEY_NAMES = re.compile(
    r"(?i).*(password|passwd|secret|api_?key|auth_?token|access_?token|client_?secret|private_?key|credentials).*"
)

MOCK_VAL_PATTERNS = re.compile(
    r"(?i)^(changeme|secret|password|admin|admin123|root|123456|test|mock|fake|dummy|sample|placeholder)$"
)


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to detect high-randomness secret strings."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {c: data.count(c) for c in set(data)}
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecretsScanner:
    """Scans YAML/JSON configurations for credentials, leaked secrets, and mock keys."""

    @classmethod
    def scan_file(cls, path: Path) -> list[Finding]:
        """Scan a single YAML or JSON file."""
        try:
            _, entries = ConfigParser.parse_file(path)
        except Exception as err:
            return [
                Finding(
                    rule_id="SEC-CFG-ERR",
                    title="Erro ao analisar arquivo de configuração",
                    description=f"Falha de sintaxe ou codificação: {err}",
                    severity=Severity.MEDIUM,
                    category=RuleCategory.CONFIG,
                    target=str(path),
                    line_number=None,
                    snippet=None,
                    remediation="Corrija os erros de sintaxe no arquivo JSON/YAML.",
                )
            ]
        return cls.scan_entries(entries, target=str(path))

    @classmethod
    def scan_entries(cls, entries: list[ConfigEntry], target: str) -> list[Finding]:
        """Inspect extracted configuration entries."""
        findings: list[Finding] = []

        for entry in entries:
            val_str = str(entry.value).strip() if entry.value is not None else ""
            if not val_str:
                continue

            # 1. Check known high-confidence regex patterns
            matched_pattern = False
            for rule_id, title, pattern, severity, remediation in PATTERNS:
                if pattern.search(val_str) or pattern.search(entry.raw_line):
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            description=f"Padrão de segredo identificado na chave '{entry.key_path}'.",
                            severity=severity,
                            category=RuleCategory.SECRETS,
                            target=target,
                            line_number=entry.line_number,
                            snippet=cls._mask_secret(entry.raw_line),
                            remediation=remediation,
                        )
                    )
                    matched_pattern = True
                    break

            if matched_pattern:
                continue

            # 2. Check sensitive key names with hardcoded or mocked secrets
            if SENSITIVE_KEY_NAMES.match(entry.key_path):
                # Is it a placeholder/mock value or a real plain text secret?
                is_mock = bool(MOCK_VAL_PATTERNS.match(val_str))
                severity = Severity.HIGH if not is_mock else Severity.MEDIUM
                title = (
                    "Segredo/chave mockada ou default em configuração"
                    if is_mock
                    else "Senha ou credencial sensível em texto claro"
                )
                desc = (
                    f"A chave '{entry.key_path}' contém um valor padrão/mock ('{val_str}') "
                    "que pode ser esquecido e enviado para produção."
                    if is_mock
                    else f"A chave sensível '{entry.key_path}' contém um valor em texto claro persistido."
                )

                findings.append(
                    Finding(
                        rule_id="SEC-SEC-006",
                        title=title,
                        description=desc,
                        severity=severity,
                        category=RuleCategory.SECRETS,
                        target=target,
                        line_number=entry.line_number,
                        snippet=cls._mask_secret(entry.raw_line),
                        remediation=(
                            "Remova credenciais estáticas do arquivo. Utilize injeção via variáveis de "
                            "ambiente ou serviços de secrets management (HashiCorp Vault, AWS Secrets Manager)."
                        ),
                    )
                )

            # 3. High entropy string check on long string values
            elif len(val_str) >= 24 and " " not in val_str:
                entropy = calculate_shannon_entropy(val_str)
                if entropy > 4.5:
                    findings.append(
                        Finding(
                            rule_id="SEC-SEC-007",
                            title="Valor com alta entropia (possível segredo ou chave privada)",
                            description=(
                                f"A chave '{entry.key_path}' possui entropia calculada de {entropy:.2f}, "
                                "indicando alta aleatoriedade típica de segredos gerados criptograficamente."
                            ),
                            severity=Severity.HIGH,
                            category=RuleCategory.SECRETS,
                            target=target,
                            line_number=entry.line_number,
                            snippet=cls._mask_secret(entry.raw_line),
                            remediation="Verifique se este valor é um segredo e extraia para variáveis de ambiente.",
                        )
                    )

        return findings

    @staticmethod
    def _mask_secret(text: str) -> str:
        """Mask potential secrets in snippet to prevent exposing them in terminal outputs."""
        if len(text) <= 12:
            return "***"
        prefix = text[:6]
        suffix = text[-4:]
        return f"{prefix}****[REDACTED]****{suffix}"
