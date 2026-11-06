"""Inspection rules for Dockerfiles."""

import re
from pathlib import Path

from cloudsec.models.finding import Finding, RuleCategory, Severity
from cloudsec.parsers.dockerfile import DockerfileInstruction, DockerfileParser

DANGEROUS_PORTS: dict[str, tuple[Severity, str]] = {
    "22": (
        Severity.HIGH,
        "Porta 22 (SSH) exposta em contêiner; utilize ferramentas de orquestração ou bastion.",
    ),
    "23": (Severity.CRITICAL, "Porta 23 (Telnet) não criptografada exposta."),
    "3389": (Severity.HIGH, "Porta 3389 (RDP) exposta."),
    "21": (Severity.HIGH, "Porta 21 (FTP) exposta sem criptografia."),
    "2375": (Severity.CRITICAL, "Porta 2375 (Docker Daemon não-TLS) exposta."),
    "2376": (Severity.HIGH, "Porta 2376 (Docker Daemon TLS) exposta diretamente."),
    "3306": (Severity.MEDIUM, "Porta padrão 3306 (MySQL) exposta; garanta rede interna isolada."),
    "5432": (
        Severity.MEDIUM,
        "Porta padrão 5432 (PostgreSQL) exposta; garanta rede interna isolada.",
    ),
    "6379": (Severity.MEDIUM, "Porta padrão 6379 (Redis) exposta sem autenticação de rede."),
    "27017": (Severity.MEDIUM, "Porta padrão 27017 (MongoDB) exposta diretamente."),
}

SECRET_ENV_PATTERN = re.compile(
    r"(?i)(password|secret|token|api_?key|private_?key|auth|access_?key|secret_?key)\s*[:=]\s*['\"]?([^'\"\s]{3,})['\"]?"
)


class DockerfileScanner:
    """Evaluates Dockerfiles against cloud security best practices."""

    @classmethod
    def scan_file(cls, path: Path) -> list[Finding]:
        """Scan a Dockerfile by filesystem path."""
        instructions = DockerfileParser.parse_file(path)
        return cls.scan_instructions(instructions, target=str(path))

    @classmethod
    def scan_instructions(
        cls, instructions: list[DockerfileInstruction], target: str = "Dockerfile"
    ) -> list[Finding]:
        """Scan a list of DockerfileInstruction objects."""
        findings: list[Finding] = []

        last_user_directive = None
        has_user_directive = False

        for inst in instructions:
            op = inst.instruction
            args = inst.arguments
            line = inst.line_number
            raw = inst.raw_content

            # Rule SEC-DKR-003: Floating :latest tag or untagged base image
            if op == "FROM":
                cls._check_base_image(args, line, raw, target, findings)

            # Track USER directives
            if op == "USER":
                has_user_directive = True
                last_user_directive = (args.strip(), line, raw)

            # Rule SEC-DKR-002: Dangerous / Sensitive Ports
            if op == "EXPOSE":
                cls._check_exposed_ports(args, line, raw, target, findings)

            # Rule SEC-DKR-004: Insecure execution (curl | bash, wget | sh)
            if op == "RUN":
                cls._check_insecure_commands(args, line, raw, target, findings)

            # Rule SEC-DKR-005: Use of ADD instead of COPY for local files
            if op == "ADD":
                cls._check_add_directive(args, line, raw, target, findings)

            # Rule SEC-DKR-006: Hardcoded secrets in ENV or ARG
            if op in ("ENV", "ARG"):
                cls._check_env_secrets(args, line, raw, target, findings)

        # Rule SEC-DKR-001: Execution as root user
        if not has_user_directive:
            findings.append(
                Finding(
                    rule_id="SEC-DKR-001",
                    title="Contêiner executando como usuário root por padrão",
                    description=(
                        "O Dockerfile não define nenhuma instrução USER não-root. "
                        "Processos em execução terão privilégios de superusuário (root)."
                    ),
                    severity=Severity.HIGH,
                    category=RuleCategory.DOCKERFILE,
                    target=target,
                    line_number=None,
                    snippet=None,
                    remediation="Adicione uma diretiva 'USER <non-root-user>' antes do ENTRYPOINT/CMD.",
                )
            )
        elif last_user_directive:
            user_val, user_line, user_snippet = last_user_directive
            if user_val.lower() in ("root", "0", "root:root"):
                findings.append(
                    Finding(
                        rule_id="SEC-DKR-001",
                        title="Contêiner configurado explicitamente para executar como root",
                        description=f"A instrução USER define explicitamente '{user_val}'.",
                        severity=Severity.HIGH,
                        category=RuleCategory.DOCKERFILE,
                        target=target,
                        line_number=user_line,
                        snippet=user_snippet,
                        remediation="Substitua por um usuário com privilégios reduzidos (ex: appuser, 10001).",
                    )
                )

        return findings

    @staticmethod
    def _check_base_image(
        args: str, line: int, snippet: str, target: str, findings: list[Finding]
    ) -> None:
        parts = args.split()
        if not parts:
            return
        image = parts[0]
        # Ignore multi-stage build references like 'FROM builder AS runner'
        if image.lower() in ("scratch",):
            return

        if ":" not in image or image.endswith(":latest"):
            findings.append(
                Finding(
                    rule_id="SEC-DKR-003",
                    title="Uso de imagem base com tag ':latest' ou sem versão fixa",
                    description=(
                        f"A imagem base '{image}' utiliza a tag mutable ':latest' ou não especifica versão, "
                        "o que prejudica a reprodutibilidade e introduz riscos de vulnerabilidades inesperadas."
                    ),
                    severity=Severity.MEDIUM,
                    category=RuleCategory.DOCKERFILE,
                    target=target,
                    line_number=line,
                    snippet=snippet,
                    remediation="Fixe uma versão semântica imutável ou digest SHA256 (ex: python:3.12-slim).",
                )
            )

    @staticmethod
    def _check_exposed_ports(
        args: str, line: int, snippet: str, target: str, findings: list[Finding]
    ) -> None:
        # Ports can be specified like: EXPOSE 80 443 22/tcp
        port_tokens = args.split()
        for token in port_tokens:
            clean_port = token.split("/")[0].strip()
            if clean_port in DANGEROUS_PORTS:
                severity, msg = DANGEROUS_PORTS[clean_port]
                findings.append(
                    Finding(
                        rule_id="SEC-DKR-002",
                        title=f"Porta sensível exposta: {clean_port}",
                        description=msg,
                        severity=severity,
                        category=RuleCategory.DOCKERFILE,
                        target=target,
                        line_number=line,
                        snippet=snippet,
                        remediation=f"Remova a exposição direta da porta {clean_port} do Dockerfile.",
                    )
                )

    @staticmethod
    def _check_insecure_commands(
        args: str, line: int, snippet: str, target: str, findings: list[Finding]
    ) -> None:
        pipe_bash_pattern = re.compile(r"(curl|wget)\s+[^|]+\|\s*(sh|bash|zsh)")
        if pipe_bash_pattern.search(args):
            findings.append(
                Finding(
                    rule_id="SEC-DKR-004",
                    title="Download e execução direta de script remoto (curl/wget | sh)",
                    description=(
                        "Executar scripts remotos diretamente via pipe para o shell impede validação de "
                        "integridade (checksum) e facilita ataques Man-in-the-Middle ou comprometimento upstream."
                    ),
                    severity=Severity.CRITICAL,
                    category=RuleCategory.DOCKERFILE,
                    target=target,
                    line_number=line,
                    snippet=snippet,
                    remediation="Faça o download do arquivo, valide a assinatura SHA256/GPG e só depois execute.",
                )
            )

    @staticmethod
    def _check_add_directive(
        args: str, line: int, snippet: str, target: str, findings: list[Finding]
    ) -> None:
        # If it's a URL or tarball, ADD might be intentional, otherwise COPY is preferred
        if not (args.startswith("http://") or args.startswith("https://") or ".tar" in args):
            findings.append(
                Finding(
                    rule_id="SEC-DKR-005",
                    title="Uso da diretiva ADD em vez de COPY",
                    description=(
                        "A diretiva ADD possui comportamentos adicionais implícitos como extração de tarballs "
                        "e download de URLs que podem gerar vulnerabilidades inesperadas."
                    ),
                    severity=Severity.LOW,
                    category=RuleCategory.DOCKERFILE,
                    target=target,
                    line_number=line,
                    snippet=snippet,
                    remediation="Substitua 'ADD' por 'COPY' para cópia simples de arquivos e pastas locais.",
                )
            )

    @staticmethod
    def _check_env_secrets(
        args: str, line: int, snippet: str, target: str, findings: list[Finding]
    ) -> None:
        match = SECRET_ENV_PATTERN.search(args)
        if match:
            findings.append(
                Finding(
                    rule_id="SEC-DKR-006",
                    title="Segredo ou credencial potencialmente exposto em diretiva ENV/ARG",
                    description=(
                        "Instruções ENV e ARG persistem nos metadados da imagem Docker e podem ser facilmente "
                        "inspecionadas via 'docker inspect' ou 'docker history'."
                    ),
                    severity=Severity.CRITICAL,
                    category=RuleCategory.DOCKERFILE,
                    target=target,
                    line_number=line,
                    snippet=snippet,
                    remediation="Utilize segredos em tempo de montagem (BuildKit '--mount=type=secret') ou variáveis em runtime.",
                )
            )
