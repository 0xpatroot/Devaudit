import os
import json
import datetime
from typing import List, Dict
from devaudit.modules.base_check import Finding, Severity
from devaudit.core.config import config

class Reporter:
    def __init__(self):
        pass

    def get_summary_counts(self, findings: List[Finding]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity.value] += 1
        return counts

    def print_to_terminal(self, findings: List[Finding], target: str):
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text

        console = Console()
        counts = self.get_summary_counts(findings)

        banner = config.t("cli.banner", version="1.0.0")
        project_str = config.t("cli.project", project=os.path.abspath(target))
        date_str = config.t("cli.date", date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        console.print(Panel(f"[bold green]{banner}[/bold green]\n{project_str}\n{date_str}", expand=False))

        categorized: Dict[str, List[Finding]] = {}
        for f in findings:
            module = f.check_name.split(":")[0]
            if module not in categorized:
                categorized[module] = []
            categorized[module].append(f)

        for module, module_findings in categorized.items():
            header_key = f"cli.scanning_{module}"

            header_text = config.t(header_key)
            if header_text == header_key:
                header_text = f"🔍 SCANNING {module.upper()}..."
            console.print(f"\n[bold blue]{header_text}[/bold blue]\n")

            for f in module_findings:
                sev_color = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "green",
                    Severity.INFO: "blue"
                }[f.severity]

                prefix = {
                    Severity.CRITICAL: "❌ CRITICAL",
                    Severity.HIGH: "⚠️  HIGH",
                    Severity.MEDIUM: "⚠️  MEDIUM",
                    Severity.LOW: "✅ LOW",
                    Severity.INFO: "ℹ️  INFO"
                }[f.severity]

                loc = f.file_path
                if f.line_number:
                    loc += f" (line {f.line_number})"

                console.print(f"  [{sev_color}]{prefix}[/{sev_color}]   [bold]{loc}[/bold]: {f.description}")
                if f.content:
                    console.print(f"     [dim]content: {f.content}[/dim]")
                if f.reference:
                    console.print(f"     [dim]ref: {f.reference}[/dim]")

        console.print(f"\n[bold]{config.t('cli.summary')}[/bold]")
        summary_counts_str = config.t(
            "cli.summary_counts",
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
            info=counts["INFO"]
        )
        console.print(summary_counts_str)

        if any(f.fixable for f in findings):
            console.print(f"\n[bold green]{config.t('cli.remediation_tip')}[/bold green]")

    def export_json(self, findings: List[Finding], output_path: str, target: str):
        counts = self.get_summary_counts(findings)
        data = {
            "meta": {
                "project": os.path.abspath(target),
                "timestamp": datetime.datetime.now().isoformat(),
                "version": "1.0.0",
                "summary": counts
            },
            "findings": [
                {
                    "check_name": f.check_name,
                    "severity": f.severity.value,
                    "description": f.description,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "content": f.content,
                    "reference": f.reference,
                    "fixable": f.fixable
                }
                for f in findings
            ]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def export_html(self, findings: List[Finding], output_path: str, target: str):
        counts = self.get_summary_counts(findings)

        rows_html = ""
        for idx, f in enumerate(findings):
            sev_class = f.severity.value.lower()
            badge_icon = {
                "critical": "☠️", "high": "🚨", "medium": "⚠️", "low": "🛡️", "info": "ℹ️"
            }.get(sev_class, "❓")

            line_info = f"Line {f.line_number}" if f.line_number else "N/A"
            code_snippet = f"<pre><code>{f.content}</code></pre>" if f.content else ""
            ref_link = f"<a href='{f.reference}' target='_blank'>Docs</a>" if f.reference else "None"
            fix_badge = "<span class='badge-fixable'>Fixable</span>" if f.fixable else ""

            rows_html += f"""
            <tr class="severity-{sev_class}">
                <td><span class="badge {sev_class}">{badge_icon} {f.severity.value}</span></td>
                <td><strong>{f.check_name}</strong> {fix_badge}</td>
                <td><span class="file-path">{f.file_path}</span> <span class="line-no">{line_info}</span></td>
                <td>
                    <div class="desc-text">{f.description}</div>
                    {code_snippet}
                </td>
                <td>{ref_link}</td>
            </tr>
            """

        is_rtl = "rtl" if config.language == "ar" else "ltr"
        align_style = "text-align: right;" if is_rtl == "rtl" else "text-align: left;"

        html_content = f"""<!DOCTYPE html>
<html lang="{config.language}" dir="{is_rtl}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevAudit Security Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-color: #0b0f19;
            --panel-bg: rgba(255, 255, 255, 0.03);
            --border-color: rgba(255, 255, 255, 0.08);
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-medium: #eab308;
            --color-low: #22c55e;
            --color-info: #3b82f6;
        }}

        body {{
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 2rem;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(147, 51, 234, 0.1));
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            backdrop-filter: blur(10px);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .header-title h1 {{
            margin: 0 0 0.5rem 0;
            font-size: 2.2rem;
            background: linear-gradient(to right, #60a5fa, #c084fc);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .header-title p {{
            margin: 0;
            color: var(--text-secondary);
        }}

        .meta-details {{
            text-align: right;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .meta-details div {{
            margin-bottom: 0.25rem;
        }}

        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}

        .card {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
            transition: all 0.3s ease;
        }}

        .card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.3);
        }}

        .card .count {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}

        .card .label {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .card.critical .count {{ color: var(--color-critical); }}
        .card.high .count {{ color: var(--color-high); }}
        .card.medium .count {{ color: var(--color-medium); }}
        .card.low .count {{ color: var(--color-low); }}
        .card.info .count {{ color: var(--color-info); }}

        .table-container {{
            background: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            overflow: hidden;
            backdrop-filter: blur(10px);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            {align_style}
        }}

        th, td {{
            padding: 1.25rem;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background-color: rgba(255, 255, 255, 0.02);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        tr:hover {{
            background-color: rgba(255, 255, 255, 0.01);
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge.critical {{ background-color: rgba(239, 68, 68, 0.15); color: var(--color-critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge.high {{ background-color: rgba(249, 115, 22, 0.15); color: var(--color-high); border: 1px solid rgba(249, 115, 22, 0.3); }}
        .badge.medium {{ background-color: rgba(234, 179, 8, 0.15); color: var(--color-medium); border: 1px solid rgba(234, 179, 8, 0.3); }}
        .badge.low {{ background-color: rgba(34, 197, 94, 0.15); color: var(--color-low); border: 1px solid rgba(34, 197, 94, 0.3); }}
        .badge.info {{ background-color: rgba(59, 130, 246, 0.15); color: var(--color-info); border: 1px solid rgba(59, 130, 246, 0.3); }}

        .badge-fixable {{
            background-color: rgba(168, 85, 247, 0.15);
            color: #c084fc;
            border: 1px solid rgba(168, 85, 247, 0.3);
            padding: 0.1rem 0.4rem;
            border-radius: 4px;
            font-size: 0.7rem;
            margin-left: 0.5rem;
        }}

        .file-path {{
            color: var(--text-primary);
            font-weight: 500;
        }}

        .line-no {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            background-color: rgba(255,255,255,0.05);
            padding: 0.1rem 0.3rem;
            border-radius: 4px;
        }}

        pre {{
            background-color: #030712;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.75rem;
            margin: 0.5rem 0 0 0;
            overflow-x: auto;
        }}

        code {{
            font-family: 'Courier New', Courier, monospace;
            font-size: 0.85rem;
            color: #38bdf8;
        }}

        a {{
            color: #60a5fa;
            text-decoration: none;
            font-weight: 500;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .desc-text {{
            font-size: 0.95rem;
            margin-bottom: 0.25rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🛡️ DevAudit Report</h1>
                <p>Offline Security & Privacy Repository Scan</p>
            </div>
            <div class="meta-details">
                <div><strong>Project:</strong> {os.path.abspath(target)}</div>
                <div><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                <div><strong>Version:</strong> v1.0.0</div>
            </div>
        </header>

        <div class="summary-cards">
            <div class="card critical">
                <div class="count">{counts["CRITICAL"]}</div>
                <div class="label">Critical</div>
            </div>
            <div class="card high">
                <div class="count">{counts["HIGH"]}</div>
                <div class="label">High</div>
            </div>
            <div class="card medium">
                <div class="count">{counts["MEDIUM"]}</div>
                <div class="label">Medium</div>
            </div>
            <div class="card low">
                <div class="count">{counts["LOW"]}</div>
                <div class="label">Low</div>
            </div>
            <div class="card info">
                <div class="count">{counts["INFO"]}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 15%;">Severity</th>
                        <th style="width: 20%;">Check Module</th>
                        <th style="width: 25%;">Location</th>
                        <th style="width: 32%;">Finding Details</th>
                        <th style="width: 8%;">Ref</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html if findings else "<tr><td colspan='5' style='text-align: center; color: var(--text-secondary);'>No issues found. Your project looks secure! ✅</td></tr>"}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def export_pdf(self, findings: List[Finding], output_path: str, target: str):

        counts = self.get_summary_counts(findings)
        try:

            pdf_lines = [
                "%PDF-1.4",
                "1 0 obj",
                "<< /Type /Catalog /Pages 2 0 R >>",
                "endobj",
                "2 0 obj",
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                "endobj",
                "3 0 obj",
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>",
                "endobj",
                "4 0 obj"
            ]

            content = "BT\n/F1 14 Tf\n50 800 Td\n(DevAudit Security Report) Tj\n"
            content += "0 -30 Td\n(========================================) Tj\n"
            content += f"0 -20 Td\n(Project: {os.path.abspath(target)[:50]}) Tj\n"
            content += f"0 -20 Td\n(Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) Tj\n"
            content += f"0 -30 Td\n(SUMMARY OF FINDINGS:) Tj\n"
            content += f"0 -20 Td\n(  Critical: {counts['CRITICAL']}   High: {counts['HIGH']}   Medium: {counts['MEDIUM']}   Low: {counts['LOW']}   Info: {counts['INFO']}) Tj\n"
            content += "0 -30 Td\n(Findings Details:) Tj\n"

            y_offset = 200
            for idx, f in enumerate(findings[:15]):
                desc = f.description[:60].replace("(", "\\(").replace(")", "\\)")
                content += f"0 -15 Td\n( - [{f.severity.value}] {f.check_name}: {desc}) Tj\n"

            content += "ET"

            pdf_lines.append(f"<< /Length {len(content)} >>")
            pdf_lines.append("stream")
            pdf_lines.append(content)
            pdf_lines.append("endstream")
            pdf_lines.append("endobj")

            pdf_lines.append("xref")
            pdf_lines.append("0 5")
            pdf_lines.append("0000000000 65535 f ")

            pdf_lines.append("trailer")
            pdf_lines.append("<< /Size 5 /Root 1 0 R >>")
            pdf_lines.append("startxref")
            pdf_lines.append("0")
            pdf_lines.append("%%EOF")

            with open(output_path, "wb") as f:
                f.write(("\n".join(pdf_lines)).encode("utf-8", errors="ignore"))
        except Exception:

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"DevAudit Security Report\n===================\nProject: {target}\nDate: {datetime.datetime.now()}\nCritical: {counts['CRITICAL']}, High: {counts['HIGH']}\n")

    def export_sarif(self, findings: List[Finding], output_path: str, target: str):
        rules = {}
        results = []

        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }

        for f in findings:
            rule_id = f.check_name
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": f.description
                    },
                    "helpUri": f.reference or "https://github.com/devaudit-project/devaudit"
                }

            level = severity_map.get(f.severity, "warning")

            file_path = f.file_path or target
            rel_uri = os.path.relpath(file_path, target).replace("\\", "/")
            if rel_uri.startswith("./") or rel_uri.startswith(".\\"):
                rel_uri = rel_uri[2:]

            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rel_uri
                    }
                }
            }

            if f.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": f.line_number
                }

            results.append({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f.description
                },
                "locations": [location]
            })

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemes/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DevAudit",
                            "semanticVersion": "1.0.0",
                            "rules": list(rules.values())
                        }
                    },
                    "results": results
                }
            ]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)

reporter = Reporter()
