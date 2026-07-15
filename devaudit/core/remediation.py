import os
import json
import click
from devaudit.core.config import config

def fix_npm_dependency(payload) -> bool:
    file_path = payload.get("file_path")
    package = payload.get("package")
    safe_version = payload.get("safe_version")

    if not file_path or not os.path.exists(file_path):
        return False

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        updated = False
        if "dependencies" in data and package in data["dependencies"]:

            prefix = ""
            current = data["dependencies"][package]
            if current.startswith("^"):
                prefix = "^"
            elif current.startswith("~"):
                prefix = "~"
            data["dependencies"][package] = f"{prefix}{safe_version}"
            updated = True

        if "devDependencies" in data and package in data["devDependencies"]:
            prefix = ""
            current = data["devDependencies"][package]
            if current.startswith("^"):
                prefix = "^"
            elif current.startswith("~"):
                prefix = "~"
            data["devDependencies"][package] = f"{prefix}{safe_version}"
            updated = True

        if updated:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
    except Exception:
        pass
    return False

def fix_pypi_dependency(payload) -> bool:
    file_path = payload.get("file_path")
    package = payload.get("package")
    safe_version = payload.get("safe_version")
    line_number = payload.get("line_number")

    if not file_path or not os.path.exists(file_path):
        return False

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if line_number and 1 <= line_number <= len(lines):
            idx = line_number - 1
            line = lines[idx]

            if package in line.lower():

                import re
                match = re.search(r"(==|>=|<=|>|<)", line)
                if match:
                    op = match.group(1)

                    parts = line.split(op, 1)

                    rest = parts[1]
                    comment = ""
                    if "#" in rest:
                        rest, comment = rest.split("#", 1)
                        comment = f" #{comment}"
                    lines[idx] = f"{parts[0]}=={safe_version}{comment.rstrip()}\n"

                    with open(file_path, "w", encoding="utf-8") as f:
                        f.writelines(lines)
                    return True
    except Exception:
        pass
    return False

def remediate_issues(issue_filter=None):
    from devaudit.cli import load_cache
    findings, target = load_cache()

    fixable_findings = [f for f in findings if f.fixable]

    if not fixable_findings:
        click.echo("No fixable security issues found in the last scan.")
        return

    fixed_count = 0
    for f in fixable_findings:

        if issue_filter and f.check_name != issue_filter:
            continue

        payload = f.fix_payload
        ecosystem = payload.get("ecosystem")
        success = False

        if ecosystem == "npm":
            success = fix_npm_dependency(payload)
        elif ecosystem == "pypi":
            success = fix_pypi_dependency(payload)

        if success:
            click.echo(config.t("cli.fix_success", issue=f.check_name))
            fixed_count += 1
        else:
            click.echo(config.t("cli.fix_fail", issue=f.check_name, reason="Could not modify file or invalid payload"))

    if fixed_count > 0:
        click.echo(f"\nAuto-remediation completed: {fixed_count} issue(s) successfully fixed.")
    else:
        click.echo("\nNo issues were modified.")
