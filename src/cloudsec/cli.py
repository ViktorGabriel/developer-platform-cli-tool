"""Command-line interface entry point for CloudSec & Container Audit CLI."""

import time
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from cloudsec import __version__
from cloudsec.models.finding import AuditSummary, Finding
from cloudsec.models.report import AuditReport
from cloudsec.parsers.container import ContainerParser
from cloudsec.reporters.json_reporter import JsonReporter
from cloudsec.reporters.markdown_reporter import MarkdownReporter
from cloudsec.reporters.terminal_reporter import TerminalReporter
from cloudsec.scanners.container_rules import ContainerScanner
from cloudsec.scanners.dockerfile_rules import DockerfileScanner
from cloudsec.scanners.secrets_rules import SecretsScanner

app = typer.Typer(
    name="cloudsec",
    help="CloudSec & Container Audit CLI - Auditoria estática e dinâmica para Dockerfiles, containers e configurações.",
    add_completion=False,
)
console = Console()


class OutputFormat(StrEnum):
    """Supported output formats for reports."""

    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"


def _emit_report(
    findings: list[Finding],
    targets_count: int,
    duration: float,
    output_format: OutputFormat,
    output_file: Path | None,
    fail_on_critical: bool,
) -> None:
    """Format and output report according to user preferences, handling exit codes."""
    summary = AuditSummary.from_findings(
        findings=findings,
        targets_scanned=targets_count,
        duration=duration,
    )
    report = AuditReport(
        version=__version__,
        summary=summary,
        findings=findings,
    )

    content = ""
    if output_format == OutputFormat.TABLE:
        TerminalReporter(console=console).print_report(report)
        if output_file:
            # Also save table text or markdown if requested with output file
            content = MarkdownReporter.render(report)
    elif output_format == OutputFormat.JSON:
        content = JsonReporter.render(report)
        if not output_file:
            print(content)
    elif output_format == OutputFormat.MARKDOWN:
        content = MarkdownReporter.render(report)
        if not output_file:
            print(content)

    if output_file and content:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(content, encoding="utf-8")
        console.print(f"[bold green]✔ Relatório salvo com sucesso em:[/bold green] {output_file}")

    if fail_on_critical and report.has_critical_or_high():
        console.print(
            "[bold red]❌ Falha na auditoria: Vulnerabilidades com severidade CRITICAL ou HIGH foram detectadas.[/bold red]"
        )
        raise typer.Exit(code=1)


@app.command("version")
def version() -> None:
    """Exibe a versão atual do CloudSec CLI."""
    console.print(f"[bold cyan]CloudSec & Container Audit CLI[/bold cyan] v{__version__}")


@app.command("scan-dockerfile")
def scan_dockerfile(
    dockerfile_path: Annotated[
        Path,
        typer.Argument(
            help="Caminho para o arquivo Dockerfile a ser auditado.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ] = Path("Dockerfile"),
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Formato do relatório de saída (table, json, markdown).",
        ),
    ] = OutputFormat.TABLE,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Caminho do arquivo para salvar o relatório.",
        ),
    ] = None,
    fail_on_critical: Annotated[
        bool,
        typer.Option(
            "--fail-on-critical",
            help="Retorna código de saída 1 caso existam vulnerabilidades CRITICAL ou HIGH.",
        ),
    ] = False,
) -> None:
    """Inspeciona um Dockerfile identificando execução como root, portas sensíveis e más práticas."""
    start_time = time.perf_counter()
    findings = DockerfileScanner.scan_file(dockerfile_path)
    duration = time.perf_counter() - start_time

    _emit_report(
        findings=findings,
        targets_count=1,
        duration=duration,
        output_format=output_format,
        output_file=output_file,
        fail_on_critical=fail_on_critical,
    )


@app.command("scan-config")
def scan_config(
    config_path: Annotated[
        Path,
        typer.Argument(
            help="Caminho para o arquivo de configuração (.yaml, .yml ou .json).",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Formato do relatório de saída (table, json, markdown).",
        ),
    ] = OutputFormat.TABLE,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Caminho do arquivo para salvar o relatório.",
        ),
    ] = None,
    fail_on_critical: Annotated[
        bool,
        typer.Option(
            "--fail-on-critical",
            help="Retorna código de saída 1 caso existam vulnerabilidades CRITICAL ou HIGH.",
        ),
    ] = False,
) -> None:
    """Valida arquivos de configuração YAML/JSON em busca de segredos vazados e chaves mockadas."""
    start_time = time.perf_counter()
    findings = SecretsScanner.scan_file(config_path)
    duration = time.perf_counter() - start_time

    _emit_report(
        findings=findings,
        targets_count=1,
        duration=duration,
        output_format=output_format,
        output_file=output_file,
        fail_on_critical=fail_on_critical,
    )


@app.command("scan-containers")
def scan_containers(
    container_id: Annotated[
        str | None,
        typer.Option(
            "--container-id",
            "-c",
            help="ID ou nome de um contêiner específico para auditoria.",
        ),
    ] = None,
    all_containers: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="Auditar também contêineres parados/interrompidos.",
        ),
    ] = False,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Formato do relatório de saída (table, json, markdown).",
        ),
    ] = OutputFormat.TABLE,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Caminho do arquivo para salvar o relatório.",
        ),
    ] = None,
    fail_on_critical: Annotated[
        bool,
        typer.Option(
            "--fail-on-critical",
            help="Retorna código de saída 1 caso existam vulnerabilidades CRITICAL ou HIGH.",
        ),
    ] = False,
) -> None:
    """Inspeciona contêineres Docker locais identificando usuários root, portas expostas e modo privilegiado."""
    start_time = time.perf_counter()
    try:
        parser = ContainerParser()
        containers = parser.list_containers(
            all_containers=all_containers, container_id=container_id
        )
    except Exception as err:
        console.print(f"[bold red]Erro ao inspecionar contêineres:[/bold red] {err}")
        raise typer.Exit(code=2) from err

    findings: list[Finding] = []
    for c in containers:
        findings.extend(ContainerScanner.scan_container(c))

    duration = time.perf_counter() - start_time
    _emit_report(
        findings=findings,
        targets_count=len(containers),
        duration=duration,
        output_format=output_format,
        output_file=output_file,
        fail_on_critical=fail_on_critical,
    )


@app.command("scan-all")
def scan_all(
    directory: Annotated[
        Path,
        typer.Argument(
            help="Diretório raiz para varredura completa de Dockerfiles e configurações.",
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
        ),
    ] = Path("."),
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Formato do relatório de saída (table, json, markdown).",
        ),
    ] = OutputFormat.TABLE,
    output_file: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Caminho do arquivo para salvar o relatório.",
        ),
    ] = None,
    fail_on_critical: Annotated[
        bool,
        typer.Option(
            "--fail-on-critical",
            help="Retorna código de saída 1 caso existam vulnerabilidades CRITICAL ou HIGH.",
        ),
    ] = False,
) -> None:
    """Executa auditoria abrangente em todos os Dockerfiles e arquivos YAML/JSON do diretório."""
    start_time = time.perf_counter()
    findings: list[Finding] = []
    targets_count = 0

    ignored_dirs = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".pytest_cache",
        ".mypy_cache",
    }

    for path in directory.rglob("*"):
        if any(ignored in path.parts for ignored in ignored_dirs):
            continue

        if path.is_file():
            # Check if Dockerfile
            if path.name.lower() == "dockerfile" or path.name.lower().endswith(".dockerfile"):
                targets_count += 1
                findings.extend(DockerfileScanner.scan_file(path))
            # Check if YAML/JSON
            elif path.suffix.lower() in (".yaml", ".yml", ".json"):
                targets_count += 1
                findings.extend(SecretsScanner.scan_file(path))

    duration = time.perf_counter() - start_time
    _emit_report(
        findings=findings,
        targets_count=targets_count,
        duration=duration,
        output_format=output_format,
        output_file=output_file,
        fail_on_critical=fail_on_critical,
    )


if __name__ == "__main__":
    app()
