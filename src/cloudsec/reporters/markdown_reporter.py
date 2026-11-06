"""Markdown reporter for CloudSec audit results, suitable for CI PR comments."""

from cloudsec.models.report import AuditReport


class MarkdownReporter:
    """Generates a GitHub-flavored Markdown audit report."""

    @classmethod
    def render(cls, report: AuditReport) -> str:
        """Render AuditReport into GitHub Flavored Markdown."""
        s = report.summary
        status_badge = (
            "🔴 **STATUS: FALHA** (Vulnerabilidades Críticas ou Altas Detectadas)"
            if report.has_critical_or_high()
            else "🟢 **STATUS: SUCESSO** (Nenhuma vulnerabilidade crítica ou alta)"
        )

        lines: list[str] = [
            f"# 🛡️ Relatório de Auditoria de Segurança - {report.tool_name}",
            "",
            f"- **Versão:** v{report.version}",
            f"- **Data/Hora:** {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"- {status_badge}",
            "",
            "## 📊 Sumário Executivo",
            "",
            "| Alvos Inspecionados | Total de Achados | Critical | High | Medium | Low | Duração |",
            "| :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
            f"| {s.targets_scanned} | {s.total_findings} | {s.critical} | {s.high} | {s.medium} | {s.low} | {s.scan_duration_seconds}s |",
            "",
        ]

        if not report.findings:
            lines.extend(
                [
                    "## 🔍 Apontamentos de Segurança",
                    "",
                    "✨ **Parabéns! Nenhum apontamento de segurança foi identificado nos alvos inspecionados.**",
                    "",
                ]
            )
            return "\n".join(lines)

        lines.extend(
            [
                "## 🔍 Detalhamento de Apontamentos",
                "",
                "| Severidade | Regra | Alvo | Descrição | Remediação Recomendada |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ]
        )

        sorted_findings = sorted(report.findings, key=lambda f: f.severity.rank, reverse=True)
        for f in sorted_findings:
            loc = f.target
            if f.line_number is not None:
                loc += f":{f.line_number}"
            clean_desc = f.description.replace("|", "\\|").replace("\n", " ")
            clean_rem = f.remediation.replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| **{f.severity.value}** | `{f.rule_id}` | `{loc}` | {clean_desc} | {clean_rem} |"
            )

        lines.append("")
        return "\n".join(lines)
