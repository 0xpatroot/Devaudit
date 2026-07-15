import os
import sys
import json
import click

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

from devaudit.core.config import config
from devaudit.core.scanner import orchestrator
from devaudit.core.reporter import reporter

CACHE_FILE = ".devaudit-cache.json"

def save_cache(findings, target):
    data = {
        "target": os.path.abspath(target),
        "findings": [
            {
                "check_name": f.check_name,
                "severity": f.severity.value,
                "description": f.description,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "content": f.content,
                "reference": f.reference,
                "fixable": f.fixable,
                "fix_payload": f.fix_payload
            }
            for f in findings
        ]
    }
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def load_cache():
    if not os.path.exists(CACHE_FILE):
        return [], "."
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        from devaudit.modules.base_check import Finding, Severity
        findings = []
        for item in data.get("findings", []):
            findings.append(Finding(
                check_name=item["check_name"],
                severity=Severity[item["severity"]],
                description=item["description"],
                file_path=item["file_path"],
                line_number=item["line_number"],
                content=item["content"],
                reference=item["reference"],
                fixable=item["fixable"],
                fix_payload=item["fix_payload"]
            ))
        return findings, data.get("target", ".")
    except Exception:
        return [], "."

def show_interactive_banner():
    from rich.console import Console
    from rich.panel import Panel
    console = Console()
    if config.language == "ar":
        banner_content = (
            "[bold green]🛡️ أهلاً بك في DevAudit v1.0.0[/bold green]\n"
            "أداة الفحص الأمني والخصوصية المحلية بالكامل والمفتوحة المصدر للمطورين.\n\n"
            "[bold cyan]الأوامر الأكثر استخداماً:[/bold cyan]\n"
            "  • [bold]devaudit scan .[/bold]             - فحص المشروع الحالي بالكامل\n"
            "  • [bold]devaudit report --format=html --output=rep.html[/bold] - تصدير النتائج لتقرير ويب جذاب\n"
            "  • [bold]devaudit fix[/bold]                  - إصلاح مشاكل الاعتماديات المكتشفة تلقائياً\n"
            "  • [bold]devaudit init[/bold]                 - إنشاء ملف إعدادات افتراضي للمشروع\n\n"
            "اكتب [yellow]devaudit --help[/yellow] لرؤية قائمة الأوامر الكاملة والمساعدة بالتفصيل."
        )
    else:
        banner_content = (
            "[bold green]🛡️ Welcome to DevAudit v1.0.0[/bold green]\n"
            "The 100% offline, open-source security & privacy audit tool for developers.\n\n"
            "[bold cyan]Commonly Used Commands:[/bold cyan]\n"
            "  • [bold]devaudit scan .[/bold]             - Scan the entire current project\n"
            "  • [bold]devaudit report --format=html --output=rep.html[/bold] - Export findings to a modern HTML web report\n"
            "  • [bold]devaudit fix[/bold]                  - Auto-remediate discovered dependency issues\n"
            "  • [bold]devaudit init[/bold]                 - Initialize a default configuration file\n\n"
            "Type [yellow]devaudit --help[/yellow] to see the full list of commands and options."
        )
    console.print(Panel(banner_content, border_style="green", expand=False))

def finalize_findings(findings, target, verbose=True, severity=None):

    min_sev_str = severity or config.min_severity
    if min_sev_str:
        from devaudit.modules.base_check import Severity
        try:
            min_sev = Severity[min_sev_str.upper()]
            findings = [f for f in findings if not (f.severity < min_sev)]
        except KeyError:
            pass

    save_cache(findings, target)

    if verbose:
        reporter.print_to_terminal(findings, target)

    from devaudit.modules.base_check import Severity
    has_high_or_critical = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
    if has_high_or_critical:
        sys.exit(1)
    else:
        sys.exit(0)

@click.group(invoke_without_command=True)
@click.option("--lang", default=None, help="Set the language (en for English, ar for Arabic)")
@click.version_option(version="1.0.0", message="DevAudit v%(version)s")
@click.pass_context
def main(ctx, lang):
    """DevAudit — Offline CLI Developer Security & Privacy Audit Tool"""
    if lang:
        config.set_language(lang)
    else:
        config.set_language(config.language)

    if ctx.invoked_subcommand is None:
        show_interactive_banner()

@main.command()
def init():
    """Initialize a default configuration file .devaudit.json in the current directory"""
    config_path = os.path.join(os.getcwd(), ".devaudit.json")
    if os.path.exists(config_path):
        click.echo("Configuration file .devaudit.json already exists in the current directory.")
        return

    default_config = {
        "language": config.language,
        "min_severity": "INFO",
        "exclude": [
            "node_modules", "venv", ".venv", ".git", "dist", "build",
            ".pytest_cache", ".eggs", "devaudit.egg-info", ".devaudit-cache.json",
            "report.html", "devaudit-report.html", "devaudit.bat"
        ],
        "scans": {
            "secrets": True,
            "dependencies": True,
            "system": True,
            "git": True,
            "network": True,
            "privacy": True,
            "docker": True
        }
    }
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2, ensure_ascii=False)
        click.echo("Successfully initialized default configuration file: .devaudit.json")
    except Exception as e:
        click.echo(f"Failed to create configuration file: {str(e)}")

@main.command()
@click.argument("target", default=".")
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--exclude", multiple=True, help="List of files or directories to exclude from the scan")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def scan(target, verbose, exclude, severity):
    """Run all security and privacy audit modules against target"""
    if verbose:
        click.echo(config.t("cli.scanning"))

    exclude_list = list(exclude) if exclude else []
    if config.exclude:
        exclude_list.extend(config.exclude)

    findings = []

    results = orchestrator.run_all(target, exclude=exclude_list)
    for scanner_name, scanner_findings in results.items():
        findings.extend(scanner_findings)

    finalize_findings(findings, target, verbose=verbose, severity=severity)

@main.command()
@click.argument("target", default=".")
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--exclude", multiple=True, help="List of files or directories to exclude from the scan")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def secrets(target, verbose, exclude, severity):
    """Audit target files and directories for exposed secrets"""
    if verbose:
        click.echo(config.t("cli.scanning_secrets"))

    exclude_list = list(exclude) if exclude else []
    if config.exclude:
        exclude_list.extend(config.exclude)

    findings = orchestrator.run_scanner("secrets", target, exclude=exclude_list)
    finalize_findings(findings, target, verbose=verbose, severity=severity)

@main.command()
@click.argument("target", default="package.json")
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def deps(target, verbose, severity):
    """Audit project dependencies for known vulnerabilities"""
    if verbose:
        click.echo(config.t("cli.scanning_deps"))
    findings = orchestrator.run_scanner("deps", target)
    finalize_findings(findings, target, verbose=verbose, severity=severity)

@main.command()
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def system(verbose, severity):
    """Audit current host operating system configuration"""
    if verbose:
        click.echo(config.t("cli.scanning_system"))
    findings = orchestrator.run_scanner("system", ".")
    finalize_findings(findings, ".", verbose=verbose, severity=severity)

@main.command()
@click.argument("target", default=".")
@click.option("--depth", default=100, help="Maximum number of commits to scan in Git history")
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def git(target, depth, verbose, severity):
    """Audit git history commits and diffs for exposed secrets"""
    if verbose:
        click.echo(config.t("cli.scanning_git"))
    findings = orchestrator.run_scanner("git", target, depth=depth)
    finalize_findings(findings, target, verbose=verbose, severity=severity)

@main.command()
@click.argument("target")
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def network(target, verbose, severity):
    """Probes hostname or URL DNS settings"""
    if verbose:
        click.echo(config.t("cli.scanning_network"))
    findings = orchestrator.run_scanner("network", target)
    finalize_findings(findings, target, verbose=verbose, severity=severity)

@main.command()
@click.argument("target")
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def ssl(target, verbose, severity):
    """Probes target SSL/TLS socket configuration"""
    if verbose:
        click.echo(config.t("cli.scanning_network"))
    findings = orchestrator.run_scanner("network", target)
    finalize_findings(findings, target, verbose=verbose, severity=severity)

@main.command()
@click.option("--verbose/--quiet", default=True, help="Display detailed scan progress and findings")
@click.option("--severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), help="Filter findings by minimum severity level")
def privacy(verbose, severity):
    """Audit privacy metrics and telemetry of tools"""
    if verbose:
        click.echo(config.t("cli.scanning_privacy"))
    findings = orchestrator.run_scanner("privacy", ".")
    finalize_findings(findings, ".", verbose=verbose, severity=severity)

@main.command()
@click.option("--format", type=click.Choice(["html", "json", "pdf", "sarif"]), default="html", help="Report format")
@click.option("--output", required=True, help="Output file path")
def report(format, output):
    """Export the results of the last scan to a report file"""
    findings, target = load_cache()
    if not findings and not os.path.exists(CACHE_FILE):
        click.echo("Error: No cached scan results found. Please run a scan first.")
        return

    if format == "json":
        reporter.export_json(findings, output, target)
    elif format == "html":
        reporter.export_html(findings, output, target)
    elif format == "pdf":
        reporter.export_pdf(findings, output, target)
    elif format == "sarif":
        reporter.export_sarif(findings, output, target)

    click.echo(config.t("cli.report_saved", path=output))

@main.command()
@click.option("--issue", help="Remediate a specific issue by check name")
def fix(issue):
    """Remediate fixable issues detected in the last scan"""
    from devaudit.core.remediation import remediate_issues
    remediate_issues(issue)

if __name__ == "__main__":
    main()
