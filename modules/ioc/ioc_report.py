from __future__ import annotations

from modules.ioc.ioc_models import IOC, IOC_REPORT_GROUPS


class IOCReportBuilder:
    """
    Render extracted IOCs as Markdown -- standalone (ioc_summary.md)
    and as an "Indicators of Compromise" section appendable to the
    final AI-generated DFIR report. Pure formatting: no extraction,
    no scoring, no reasoning.
    """

    def build_markdown(self, iocs: list[IOC], *, title: str = "# Indicators of Compromise") -> str:
        lines = [title, ""]

        by_type = {}
        for ioc in iocs:
            by_type.setdefault(ioc.ioc_type, []).append(ioc)

        for group_name, ioc_types in IOC_REPORT_GROUPS.items():
            group_iocs = [ioc for t in ioc_types for ioc in by_type.get(t, [])]
            if not group_iocs:
                continue

            lines.append(f"## {group_name}")
            lines.append("")
            for ioc in sorted(group_iocs, key=lambda i: i.value):
                lines.append(self._format_line(ioc))
            lines.append("")

        if len(lines) == 2:
            lines.append("(no indicators extracted)")

        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _format_line(ioc: IOC) -> str:
        parts = [f"- `{ioc.value}`", f"(seen {ioc.count}x"]
        if ioc.severity:
            parts.append(f", severity: {ioc.severity.value}")
        if ioc.related_incident_ids:
            parts.append(f", incidents: {', '.join(sorted(ioc.related_incident_ids))[:80]}")
        parts.append(")")
        return " ".join(parts)

    def build_report_section(self, iocs: list[IOC]) -> str:
        """
        The section appended to the final DFIR report, per the
        requested format: a fenced heading, then only the groups that
        actually have extracted IOCs.
        """
        header = (
            "==============================\n"
            "Indicators of Compromise\n"
            "==============================\n"
        )
        return header + "\n" + self.build_markdown(iocs, title="")