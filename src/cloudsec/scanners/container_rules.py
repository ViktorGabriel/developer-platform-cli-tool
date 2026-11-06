"""Inspection rules for local running Docker containers."""

import re

from cloudsec.models.finding import Finding, RuleCategory, Severity
from cloudsec.parsers.container import ContainerInfo
from cloudsec.scanners.dockerfile_rules import DANGEROUS_PORTS

SECRET_ENV_REGEX = re.compile(
    r"(?i)^(password|secret|token|api_?key|private_?key|aws_access_key_id|aws_secret_access_key)=(.*)$"
)


class ContainerScanner:
    """Evaluates local container configurations and running instances."""

    @classmethod
    def scan_container(cls, container: ContainerInfo) -> list[Finding]:
        """Audit a single container instance."""
        findings: list[Finding] = []
        target = f"{container.name} ({container.id})"

        # Rule SEC-CTR-001: Container running as root
        if not container.user or container.user.lower() in ("root", "0", "0:0"):
            findings.append(
                Finding(
                    rule_id="SEC-CTR-001",
                    title="Contêiner executando como usuário root",
                    description=(
                        f"O contêiner '{container.name}' está executando sem especificação de usuário "
                        f"não-root (user='{container.user or 'root (padrão)'}'). Caso um invasor explore uma "
                        "vulnerabilidade na aplicação, terá privilégios de superusuário no contêiner."
                    ),
                    severity=Severity.HIGH,
                    category=RuleCategory.CONTAINER,
                    target=target,
                    line_number=None,
                    snippet=f"User: '{container.user or 'root'}'",
                    remediation="Inicie o contêiner com a flag '--user <uid>:<gid>' ou defina USER no Dockerfile.",
                )
            )

        # Rule SEC-CTR-002: Container in Privileged Mode
        if container.privileged:
            findings.append(
                Finding(
                    rule_id="SEC-CTR-002",
                    title="Contêiner em execução com flag Privileged habilitada",
                    description=(
                        f"O contêiner '{container.name}' tem '--privileged' ativado. Isso desativa o "
                        "isolamento de namespaces do Linux e concede acesso quase irrestrito aos dispositivos "
                        "e recursos do host (container breakout risco crítico)."
                    ),
                    severity=Severity.CRITICAL,
                    category=RuleCategory.CONTAINER,
                    target=target,
                    line_number=None,
                    snippet="Privileged: True",
                    remediation="Remova a flag '--privileged'. Adicione somente as Linux Capabilities estritamente necessárias via '--cap-add'.",
                )
            )

        # Rule SEC-CTR-003: Sensitive port exposure or binding to all interfaces
        cls._check_container_ports(container, target, findings)

        # Rule SEC-CTR-004: Secrets directly in Environment Variables
        cls._check_container_env_vars(container, target, findings)

        return findings

    @classmethod
    def _check_container_ports(
        cls, container: ContainerInfo, target: str, findings: list[Finding]
    ) -> None:
        # Check port bindings to 0.0.0.0 or ::
        for port_proto, host_bindings in container.port_bindings.items():
            port_num = port_proto.split("/")[0]
            if host_bindings:
                for binding in host_bindings:
                    host_ip = binding.get("HostIp", "")
                    host_port = binding.get("HostPort", "")
                    if host_ip in ("0.0.0.0", "::", "") and port_num in DANGEROUS_PORTS:
                        sev, msg = DANGEROUS_PORTS[port_num]
                        findings.append(
                            Finding(
                                rule_id="SEC-CTR-003",
                                title=f"Porta sensível {port_num} vinculada a todas as interfaces ({host_ip or '0.0.0.0'}:{host_port})",
                                description=(
                                    f"O contêiner expõe a porta sensível {port_num} externamente no host. {msg}"
                                ),
                                severity=sev,
                                category=RuleCategory.CONTAINER,
                                target=target,
                                line_number=None,
                                snippet=f"Binding: {port_proto} -> {host_ip}:{host_port}",
                                remediation="Restrinja a vinculação a 127.0.0.1 ou comunique via rede interna Docker bridge.",
                            )
                        )

    @classmethod
    def _check_container_env_vars(
        cls, container: ContainerInfo, target: str, findings: list[Finding]
    ) -> None:
        for env_item in container.env_vars:
            match = SECRET_ENV_REGEX.match(env_item)
            if match:
                key, val = match.group(1), match.group(2)
                if val and len(val) > 2:
                    findings.append(
                        Finding(
                            rule_id="SEC-CTR-004",
                            title=f"Variável de ambiente com segredo em texto claro: {key}",
                            description=(
                                f"A variável '{key}' contém um segredo visível via 'docker inspect'. "
                                "Qualquer usuário ou processo com acesso ao daemon pode ler estas credenciais."
                            ),
                            severity=Severity.HIGH,
                            category=RuleCategory.CONTAINER,
                            target=target,
                            line_number=None,
                            snippet=f"{key}=******",
                            remediation="Utilize Docker Secrets (em modo Swarm) ou monte volumes tmpfs com arquivos de segredos.",
                        )
                    )
