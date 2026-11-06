"""Terminal reporter using Rich tables, panels and syntax styling."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cloudsec.models.finding import Severity
from cloudsec.models.report import AuditReport

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "bold cyan",
}


class TerminalReporter:
    """Renders formatted security reports in the terminal."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print_report(self, report: AuditReport) -> None:
        """Render the complete audit report to stdout."""
        summary = report.summary

        # Title Panel
        status_text = (
            "[bold red]FALHA: Vulnerabilidades críticas ou altas encontradas![/bold red]"
            if report.has_critical_or_high()
            else "[bold green]SUCESSO: Nenhuma vulnerabilidade crítica ou alta encontrada.[/bold green]"
        )

        title_panel = Panel(
            Text.from_markup(
                f"[bold cyan]CloudSec & Container Audit CLI[/bold cyan] v{report.version}\n"
                f"Data/Hora: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"Status: {status_text}"
            ),
            title="[bold blue]🛡️ Relatório de Auditoria de Segurança[/bold blue]",
            border_style="blue",
        )
        self.console.print(title_panel)

        # Summary Table
        summary_table = Table(title="📊 Sumário Executivo", border_style="dim")
        summary_table.add_column("Alvos Inspecionados", justify="center", style="cyan")
        summary_table.add_column("Total de Achados", justify="center", style="bold")
        summary_table.add_column("CRITICAL", justify="center", style="bold red")
        summary_table.add_column("HIGH", justify="center", style="red")
        summary_table.add_column("MEDIUM", justify="center", style="yellow")
        summary_table.add_column("LOW", justify="center", style="blue")
        summary_table.add_column("Duração (s)", justify="center", style="dim")

        summary_table.add_row(
            str(summary.targets_scanned),
            str(summary.total_findings),
            str(summary.critical),
            str(summary.high),
            str(summary.medium),
            str(summary.low),
            f"{summary.scan_duration_seconds}s",
        )
        self.console.print(summary_table)
        self.console.print("")

        # Findings Detail Table
        if not report.findings:
            self.console.print(
                "[bold green]✨ Nenhum apontamento de segurança identificado nos alvos inspecionados![/bold green]\n"
            )
            return

        findings_table = Table(
            title=f"🔍 Detalhamento de Apontamentos ({len(report.findings)})",
            show_lines=True,
            border_style="dim",
            expand=False,
        )
        findings_table.add_column("Severidade", style="bold", no_wrap=True)
        findings_table.add_column("ID / Categoria", no_wrap=True)
        findings_table.add_column("Alvo & Local", style="cyan")
        findings_table.add_column("Descrição & Remediação")

        # Sort findings by severity rank descending
        sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)

        for finding in sorted_findings:
            sev_badge = Text(
                f" {finding.severity.value} ",
                style=SEVERITY_STYLES.get(finding.severity, "white"),
            )
            id_cat = f"[bold]{finding.rule_id}[/bold]\n[dim]{finding.category.value}[/dim]"
            location = finding.target
            if finding.line_number is not None:
                location += f":L{finding.line_number}"

            desc_and_fix = (
                f"[bold]{finding.title}[/bold]\n"
                f"{finding.description}\n"
                f"[green]➜ Remediação:[/green] {finding.remediation}"
            )
            if finding.snippet:
                desc_and_fix += f"\n[dim italic]Snippet: {finding.snippet}[/dim italic]"

            findings_table.add_row(sev_badge, id_cat, location, desc_and_fix)

        self.console.print(findings_table)
        self.console.print("")
