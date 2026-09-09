from pathlib import Path
import json
import subprocess
import sys



SCAN_FILE = Path("logs/latest_chrome_inventory.json")


def read_latest_scan() -> dict:
    """Read the latest Chrome extension security scan.

    Returns:
        A dictionary containing the latest scan data.
    """

    if not SCAN_FILE.exists():
        return {
            "success": False,
            "error": f"Scan file not found: {SCAN_FILE}",
        }

    try:
        with SCAN_FILE.open("r", encoding="utf-8") as file:
            scan = json.load(file)

        return {
            "success": True,
            "scan": scan,
        }

    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "error": f"Invalid JSON in scan file: {exc}",
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Could not read scan file: {exc}",
        }


def get_extension_details(extension_id: str) -> dict:
    """Find an extension in the latest Chrome security scan.

    Args:
        extension_id: The Chrome extension ID to search for.

    Returns:
        The matching extension record, or an error if it
        cannot be found.
    """

    if not SCAN_FILE.exists():
        return {
            "success": False,
            "error": f"Scan file not found: {SCAN_FILE}",
        }

    try:
        with SCAN_FILE.open("r", encoding="utf-8") as file:
            scan = json.load(file)

        extensions = scan.get("extensions", [])

        for extension in extensions:
            if extension.get("extension_id") == extension_id:
                return {
                    "success": True,
                    "extension": extension,
                }

        return {
            "success": False,
            "error": f"Extension {extension_id} was not found in the latest scan.",
        }

    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "error": f"Invalid JSON in scan file: {exc}",
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Could not read scan file: {exc}",
        }


def get_scan_history() -> dict:
    """Return information about previous Chrome extension scans.

    The scanner stores historical events as JSONL files in
    logs/wazuh_spool/.
    """

    history_dir = Path("logs/wazuh_spool")

    if not history_dir.exists():
        return {
            "success": False,
            "error": f"Scan history directory not found: {history_dir}",
        }

    try:
        files = sorted(
            history_dir.glob("scan_*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        scans = []

        for file in files:
            scans.append({
                "filename": file.name,
                "modified_time": file.stat().st_mtime,
            })

        return {
            "success": True,
            "scan_count": len(scans),
            "scans": scans,
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Could not read scan history: {exc}",
        }


def search_scan_history(extension_id: str) -> dict:
    """Search historical JSONL scan files for an extension ID.

    Args:
        extension_id: Chrome extension ID to search for.

    Returns:
        Historical records matching the extension ID.
    """

    history_dir = Path("logs/wazuh_spool")

    if not history_dir.exists():
        return {
            "success": False,
            "error": f"Scan history directory not found: {history_dir}",
        }

    matches = []

    try:
        files = sorted(
            history_dir.glob("scan_*.jsonl"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )

        for file in files:
            try:
                with file.open("r", encoding="utf-8") as handle:
                    for line_number, line in enumerate(handle, start=1):

                        line = line.strip()

                        if not line:
                            continue

                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if record.get("extension_id") == extension_id:
                            matches.append({
                                "filename": file.name,
                                "line_number": line_number,
                                "record": record,
                            })

            except OSError:
                # If one historical file cannot be read,
                # continue searching the remaining files.
                continue

        return {
            "success": True,
            "extension_id": extension_id,
            "match_count": len(matches),
            "matches": matches,
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Could not search scan history: {exc}",
        }

def get_high_risk_extensions(limit: int = 5) -> dict:
    """Return the highest-risk extensions from the latest scan.

    Args:
        limit: Maximum number of extensions to return.

    Returns:
        A list of extensions ordered by descending risk score.
    """

    if not SCAN_FILE.exists():
        return {
            "success": False,
            "error": f"Scan file not found: {SCAN_FILE}",
        }

    try:
        with SCAN_FILE.open("r", encoding="utf-8") as file:
            scan = json.load(file)

        extensions = scan.get("extensions", [])

        # Sort using the scanner's existing risk_score.
        # Missing scores are treated as 0.
        sorted_extensions = sorted(
            extensions,
            key=lambda extension: extension.get("risk_score") or 0,
            reverse=True,
        )

        results = []

        for extension in sorted_extensions[:limit]:
            results.append({
                "extension_id": extension.get("extension_id"),
                "extension_name": extension.get("extension_name"),
                "extension_version": extension.get("extension_version"),
                "risk_score": extension.get("risk_score"),
                "severity": extension.get("severity"),
                "permissions": extension.get("permissions", []),
                "host_permissions": extension.get(
                    "host_permissions", []
                ),
                "findings": extension.get("findings", []),
            })

        return {
            "success": True,
            "count": len(results),
            "extensions": results,
        }

    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "error": f"Invalid JSON in scan file: {exc}",
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Could not read scan file: {exc}",
        }


def compare_extension_history(extension_id: str) -> dict:
    """Return one consolidated observation per scan for an extension."""

    history_dir = Path("logs/wazuh_spool")

    if not history_dir.exists():
        return {
            "success": False,
            "error": f"Scan history directory not found: {history_dir}",
        }

    scans: dict[str, dict] = {}

    try:
        files = sorted(
            history_dir.glob("scan_*.jsonl"),
            key=lambda path: path.stat().st_mtime,
        )

        for file in files:
            try:
                with file.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()

                        if not line:
                            continue

                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if record.get("extension_id") != extension_id:
                            continue

                        scan_id = record.get("scan_id")

                        if not scan_id:
                            continue

                        # Keep the most complete record for this scan.
                        existing = scans.get(scan_id)

                        candidate = {
                            "scan_id": scan_id,
                            "filename": file.name,
                            "timestamp": record.get("timestamp"),
                            "extension_name": record.get(
                                "extension_name"
                            ),
                            "extension_version": record.get(
                                "extension_version"
                            ),
                            "risk_score": record.get("risk_score"),
                            "severity": record.get("severity"),
                            "permissions": record.get(
                                "permissions", []
                            ),
                            "host_permissions": record.get(
                                "host_permissions", []
                            ),
                            "findings": record.get(
                                "findings", []
                            ),

                            "data_availability": {
                                "risk_score": record.get("risk_score") is not None,
                                 "severity": (
                                    record.get("severity") is not None
                                    and record.get("severity") != "unscored"
                                ),
                                "permissions": "permissions" in record,
                                "host_permissions": "host_permissions" in record,
                                "findings": "findings" in record,
                            },
                        }

                        if existing is None:
                            scans[scan_id] = candidate
                            continue

                        # Prefer the record containing actual
                        # security-analysis information.
                        existing_completeness = (
                            bool(existing["severity"])
                            + bool(existing["permissions"])
                            + bool(existing["host_permissions"])
                            + bool(existing["findings"])
                            + (existing["risk_score"] is not None)
                        )

                        candidate_completeness = (
                            bool(candidate["severity"])
                            + bool(candidate["permissions"])
                            + bool(candidate["host_permissions"])
                            + bool(candidate["findings"])
                            + (candidate["risk_score"] is not None)
                        )

                        if candidate_completeness > existing_completeness:
                            scans[scan_id] = candidate

            except OSError:
                continue

        history = sorted(
            scans.values(),
            key=lambda item: item.get("timestamp") or "",
        )

        return {
            "success": True,
            "extension_id": extension_id,
            "observation_count": len(history),
            "history": history,
        }

    except OSError as exc:
        return {
            "success": False,
            "error": f"Could not compare extension history: {exc}",
        }



def analyze_extension_changes(extension_id: str) -> dict:
    """Analyze changes between the oldest and newest available scans."""

    result = compare_extension_history(extension_id)

    if not result.get("success"):
        return result

    history = result.get("history", [])

    if len(history) < 2:
        return {
            "success": True,
            "extension_id": extension_id,
            "message": "Not enough historical observations to compare.",
            "changes": [],
        }

    previous = history[-2]
    current = history[-1]

    changes = []

    # Version
    if previous.get("extension_version") != current.get("extension_version"):
        changes.append({
            "field": "extension_version",
            "previous": previous.get("extension_version"),
            "current": current.get("extension_version"),
            "type": "changed",
        })

    # Severity
    previous_severity = previous.get("severity")
    current_severity = current.get("severity")

    if (
        previous_severity
        and current_severity
        and previous_severity != "unscored"
        and current_severity != "unscored"
        and previous_severity != current_severity
    ):
        changes.append({
            "field": "severity",
            "previous": previous_severity,
            "current": current_severity,
            "type": "changed",
        })

    # Risk score
    previous_risk = previous.get("risk_score")
    current_risk = current.get("risk_score")

    if previous_risk is not None and current_risk is not None:
        if previous_risk != current_risk:
            changes.append({
                "field": "risk_score",
                "previous": previous_risk,
                "current": current_risk,
                "difference": current_risk - previous_risk,
                "type": "changed",
            })
    elif previous_risk is None and current_risk is not None:
        changes.append({
            "field": "risk_score",
            "previous": None,
            "current": current_risk,
            "type": "newly_available",
        })

    # Permissions
    previous_permissions = set(previous.get("permissions", []))
    current_permissions = set(current.get("permissions", []))

    added_permissions = sorted(
        current_permissions - previous_permissions
    )
    removed_permissions = sorted(
        previous_permissions - current_permissions
    )

    if added_permissions:
        changes.append({
            "field": "permissions",
            "type": "added",
            "values": added_permissions,
        })

    if removed_permissions:
        changes.append({
            "field": "permissions",
            "type": "removed",
            "values": removed_permissions,
        })

    # Host permissions
    previous_hosts = set(previous.get("host_permissions", []))
    current_hosts = set(current.get("host_permissions", []))

    added_hosts = sorted(current_hosts - previous_hosts)
    removed_hosts = sorted(previous_hosts - current_hosts)

    if added_hosts:
        changes.append({
            "field": "host_permissions",
            "type": "added",
            "values": added_hosts,
        })

    if removed_hosts:
        changes.append({
            "field": "host_permissions",
            "type": "removed",
            "values": removed_hosts,
        })

    return {
        "success": True,
        "extension_id": extension_id,
        "previous_scan": {
            "scan_id": previous.get("scan_id"),
            "timestamp": previous.get("timestamp"),
            "version": previous.get("extension_version"),
            "severity": previous.get("severity"),
            "risk_score": previous.get("risk_score"),
        },
        "current_scan": {
            "scan_id": current.get("scan_id"),
            "timestamp": current.get("timestamp"),
            "version": current.get("extension_version"),
            "severity": current.get("severity"),
            "risk_score": current.get("risk_score"),
        },
        "change_count": len(changes),
        "changes": changes,
    }


def analyze_extension_trend(extension_id: str) -> dict:
    """Analyze an extension across its complete available scan history."""

    result = compare_extension_history(extension_id)

    if not result.get("success"):
        return result

    history = result.get("history", [])

    if len(history) < 2:
        return {
            "success": True,
            "extension_id": extension_id,
            "observation_count": len(history),
            "message": "Not enough historical observations to analyze a trend.",
            "changes": [],
        }

    changes = []

    for previous, current in zip(history, history[1:]):
        pair_changes = []

        # Version
        if (
            previous.get("extension_version")
            and current.get("extension_version")
            and previous.get("extension_version")
            != current.get("extension_version")
        ):
            pair_changes.append({
                "field": "extension_version",
                "previous": previous.get("extension_version"),
                "current": current.get("extension_version"),
            })

        # Severity
        previous_severity = previous.get("severity")
        current_severity = current.get("severity")

        if (
            previous_severity
            and current_severity
            and previous_severity != "unscored"
            and current_severity != "unscored"
            and previous_severity != current_severity
        ):
            pair_changes.append({
                "field": "severity",
                "previous": previous_severity,
                "current": current_severity,
            })

        # Risk score
        previous_risk = previous.get("risk_score")
        current_risk = current.get("risk_score")

        if previous_risk is not None and current_risk is not None:
            if previous_risk != current_risk:
                pair_changes.append({
                    "field": "risk_score",
                    "previous": previous_risk,
                    "current": current_risk,
                    "difference": current_risk - previous_risk,
                })

        # Permissions
        previous_permissions = set(
            previous.get("permissions", [])
        )
        current_permissions = set(
            current.get("permissions", [])
        )

        added_permissions = sorted(
            current_permissions - previous_permissions
        )

        removed_permissions = sorted(
            previous_permissions - current_permissions
        )

        if added_permissions:
            pair_changes.append({
                "field": "permissions",
                "type": "added",
                "values": added_permissions,
            })

        if removed_permissions:
            pair_changes.append({
                "field": "permissions",
                "type": "removed",
                "values": removed_permissions,
            })

        # Host permissions
        previous_hosts = set(
            previous.get("host_permissions", [])
        )
        current_hosts = set(
            current.get("host_permissions", [])
        )

        added_hosts = sorted(
            current_hosts - previous_hosts
        )

        removed_hosts = sorted(
            previous_hosts - current_hosts
        )

        if added_hosts:
            pair_changes.append({
                "field": "host_permissions",
                "type": "added",
                "values": added_hosts,
            })

        if removed_hosts:
            pair_changes.append({
                "field": "host_permissions",
                "type": "removed",
                "values": removed_hosts,
            })

        if pair_changes:
            changes.append({
                "from": previous.get("timestamp"),
                "to": current.get("timestamp"),
                "changes": pair_changes,
            })

    return {
        "success": True,
        "extension_id": extension_id,
        "observation_count": len(history),
        "change_events": len(changes),
        "changes": changes,
    }


def get_extension_risk_evidence(extension_id: str) -> dict:
    """Return the available security evidence for an extension."""

    result = get_extension_details(extension_id)

    if not result.get("success"):
        return result

    extension = result.get("extension")

    if not extension:
        return {
            "success": False,
            "error": "Extension details were not found.",
        }

    return {
        "success": True,
        "extension_id": extension.get("extension_id"),
        "extension_name": extension.get("extension_name"),
        "extension_version": extension.get("extension_version"),
        "severity": extension.get("severity"),
        "risk_score": extension.get("risk_score"),
        "permissions": extension.get("permissions", []),
        "host_permissions": extension.get(
            "host_permissions", []
        ),
        "findings": extension.get("findings", []),

        # Explicitly indicate whether the fields exist.
        "data_availability": {
            "risk_score": extension.get("risk_score") is not None,
            "severity": (
                extension.get("severity") is not None
                and extension.get("severity") != "unscored"
            ),
            "permissions": "permissions" in extension,
            "host_permissions": "host_permissions" in extension,
            "findings": "findings" in extension,
        },
    }



def run_scan() -> dict:
    """
    Run the existing browser-extension scanner and return
    structured information from the newest fallback JSONL scan.
    """

    import json
    import subprocess
    import sys
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[2]
    main_script = project_root / "main.py"
    spool_dir = project_root / "logs" / "wazuh_spool"

    try:
        result = subprocess.run(
            [sys.executable, str(main_script)],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "The scanner exceeded the 5-minute timeout.",
        }
    except OSError as error:
        return {
            "success": False,
            "error": f"Unable to start the scanner: {error}",
        }

    if result.returncode != 0:
        return {
            "success": False,
            "error": "The scanner exited with an error.",
            "return_code": result.returncode,
            "stdout": result.stdout[-5000:],
            "stderr": result.stderr[-5000:],
        }

    # Find the newest JSONL fallback scan.
    scan_files = list(spool_dir.glob("scan_*.jsonl"))

    if not scan_files:
        return {
            "success": False,
            "error": "The scanner completed, but no JSONL scan was found.",
        }

    latest_file = max(
        scan_files,
        key=lambda path: path.stat().st_mtime,
    )

    events = []

    try:
        with latest_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    except OSError as error:
        return {
            "success": False,
            "error": f"Unable to read scan results: {error}",
        }

    extensions = [
        event
        for event in events
        if event.get("event_type") == "extension_inventory"
    ]

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unscored": 0,
    }

    for extension in extensions:
        severity = str(
            extension.get("severity") or "Unscored"
        ).strip()

        matched = next(
            (
                key
                for key in severity_counts
                if key.lower() == severity.lower()
            ),
            "Unscored",
        )

        severity_counts[matched] += 1

    return {
        "success": True,
        "scan_file": str(latest_file),
        "scan_id": (
            extensions[0].get("scan_id")
            if extensions
            else None
        ),
        "timestamp": (
            extensions[0].get("timestamp")
            if extensions
            else None
        ),
        "browser": (
            extensions[0].get("browser")
            if extensions
            else None
        ),
        "extension_count": len(extensions),
        "severity_counts": severity_counts,
        "extensions": extensions,
    }




def generate_report() -> dict:
    """
    Generate a Markdown security report from the latest JSONL scan.

    Scanner data is authoritative.
    Missing fields are reported as unavailable.
    """

    from pathlib import Path
    import json

    spool_dir = (
        Path(__file__).resolve().parents[2]
        / "logs"
        / "wazuh_spool"
    )

    scan_files = sorted(
        spool_dir.glob("scan_*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not scan_files:
        return {
            "success": False,
            "error": "No scan files were found.",
        }

    latest_file = scan_files[0]

    extensions = []

    try:
        with latest_file.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("event_type") == "extension_inventory":
                    extensions.append(event)

    except OSError as error:
        return {
            "success": False,
            "error": f"Unable to read scan file: {error}",
        }

    if not extensions:
        return {
            "success": False,
            "error": (
                "The latest scan contains no "
                "extension inventory events."
            ),
            "scan_file": str(latest_file),
        }

    first = extensions[0]

    scan_id = first.get(
        "scan_id",
        "Unavailable",
    )

    timestamp = first.get(
        "timestamp",
        "Unavailable",
    )

    browser = first.get(
        "browser",
        "Unavailable",
    )

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unscored": 0,
    }

    for extension in extensions:
        severity = str(
            extension.get(
                "severity",
                "Unscored",
            )
        ).strip()

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["Unscored"] += 1

    suspicious_count = (
        severity_counts["Critical"]
        + severity_counts["High"]
        + severity_counts["Medium"]
    )

    scored_extensions = [
        extension
        for extension in extensions
        if isinstance(
            extension.get("permission_risk_score"),
            (int, float),
        )
    ]

    most_dangerous = None

    if scored_extensions:
        most_dangerous = max(
            scored_extensions,
            key=lambda extension:
            extension["permission_risk_score"],
        )

    report = []

    report.append("# Chrome Extension Security Report")
    report.append("")

    report.append("## Scan Information")
    report.append("")
    report.append(f"- **Scan ID:** {scan_id}")
    report.append(f"- **Date:** {timestamp}")
    report.append(f"- **Browser:** {browser}")
    report.append(
        f"- **Extensions scanned:** {len(extensions)}"
    )
    report.append("")

    report.append("## Security Summary")
    report.append("")
    report.append(
        f"- **Critical:** {severity_counts['Critical']}"
    )
    report.append(
        f"- **High:** {severity_counts['High']}"
    )
    report.append(
        f"- **Medium:** {severity_counts['Medium']}"
    )
    report.append(
        f"- **Low:** {severity_counts['Low']}"
    )
    report.append(
        f"- **Unscored:** {severity_counts['Unscored']}"
    )
    report.append(
        f"- **Requiring attention:** {suspicious_count}"
    )
    report.append("")

    # List unique extensions that require security attention.
    attention_by_id = {}

    for extension in extensions:
        severity = str(
            extension.get("severity", "")
        ).strip()

        if severity not in {
            "Critical",
            "High",
            "Medium",
        }:
            continue

        extension_id = extension.get(
            "extension_id"
        )

        if not extension_id:
            continue

        existing = attention_by_id.get(extension_id)

        if existing is None:
            attention_by_id[extension_id] = extension
            continue

        current_score = extension.get(
            "permission_risk_score"
        )

        existing_score = existing.get(
            "permission_risk_score"
        )

        # Prefer the record with the newer timestamp.
        current_timestamp = extension.get(
            "timestamp",
            "",
        )

        existing_timestamp = existing.get(
            "timestamp",
            "",
        )

        if current_timestamp > existing_timestamp:
            attention_by_id[extension_id] = extension

    attention_extensions = list(
        attention_by_id.values()
    )

    attention_extensions.sort(
        key=lambda extension: (
            -(
                extension.get(
                    "permission_risk_score",
                    -1,
                )
                if isinstance(
                    extension.get(
                        "permission_risk_score"
                    ),
                    (int, float),
                )
                else -1
            ),
            extension.get(
                "extension_name",
                "",
            ),
        )
    )

    if attention_extensions:
        report.append(
            "## Extensions Requiring Attention"
        )
        report.append("")

        for extension in attention_extensions:
            name = extension.get(
                "extension_name",
                "Unavailable",
            )

            extension_id = extension.get(
                "extension_id",
                "Unavailable",
            )

            version = extension.get(
                "extension_version",
                "Unavailable",
            )

            severity = extension.get(
                "severity",
                "Unavailable",
            )

            score = extension.get(
                "permission_risk_score",
                "Unavailable",
            )

            report.append(
                f"### {name}"
            )
            report.append("")
            report.append(
                f"- **Extension ID:** {extension_id}"
            )
            report.append(
                f"- **Version:** {version}"
            )
            report.append(
                f"- **Severity:** {severity}"
            )
            report.append(
                f"- **Risk score:** {score}"
            )
            report.append("")

    if most_dangerous:
        name = most_dangerous.get(
            "extension_name",
            "Unavailable",
        )

        extension_id = most_dangerous.get(
            "extension_id",
            "Unavailable",
        )

        version = most_dangerous.get(
            "extension_version",
            "Unavailable",
        )

        score = most_dangerous.get(
            "permission_risk_score",
            "Unavailable",
        )

        severity = most_dangerous.get(
            "severity",
            "Unavailable",
        )

        permissions = most_dangerous.get(
            "permissions",
            [],
        )

        host_permissions = most_dangerous.get(
            "host_permissions",
            [],
        )

        findings = most_dangerous.get(
            "findings",
            [],
        )

        report.append("## Highest-Risk Extension")
        report.append("")
        report.append(f"- **Extension:** {name}")
        report.append(
            f"- **Extension ID:** {extension_id}"
        )
        report.append(f"- **Version:** {version}")
        report.append(f"- **Risk score:** {score}")
        report.append(f"- **Severity:** {severity}")
        report.append("")

        report.append("### Permissions")
        report.append("")

        if permissions:
            for permission in permissions:
                report.append(f"- `{permission}`")
        else:
            report.append("- None reported")

        report.append("")

        report.append("### Host Permissions")
        report.append("")

        if host_permissions:
            for host in host_permissions:
                report.append(f"- `{host}`")
        else:
            report.append("- None reported")

        report.append("")

        report.append("### Scanner Findings")
        report.append("")

        if findings:
            for finding in findings:
                category = finding.get(
                    "category",
                    "Unknown",
                )

                item = finding.get(
                    "item",
                    "Unknown",
                )

                reason = finding.get(
                    "reason",
                    "No explanation provided.",
                )

                report.append(
                    f"- **[{category}] {item}:** "
                    f"{reason}"
                )
        else:
            report.append("- No findings reported.")

        report.append("")

    report.append("## Recommendations")
    report.append("")
    report.append(
        "- Review extensions classified as Critical "
        "or High."
    )
    report.append(
        "- Investigate broad host permissions and "
        "sensitive permissions."
    )
    report.append(
        "- Review the scanner findings before taking "
        "action."
    )
    report.append(
        "- Recommendations are security guidance, "
        "not scanner findings."
    )
    report.append("")

    report.append("## Data Availability")
    report.append("")
    report.append(
        "This report uses the scanner data available "
        "in the selected scan."
    )
    report.append(
        "Missing fields are not interpreted as zero risk."
    )

    return {
        "success": True,
        "scan_file": str(latest_file),
        "scan_id": scan_id,
        "timestamp": timestamp,
        "extension_count": len(extensions),
        "severity_counts": severity_counts,
        "report": "\n".join(report),
    }