from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from analysis_engine.extension_analyzer import ExtensionAnalyzer
from analysis_engine.threat_intel_service import ThreatIntelService
from endpoint_scanner.event_writer import JsonLinesEventWriter
from endpoint_scanner.inventory_comparator import InventoryComparator
from endpoint_scanner.ioc_extractor import IOCExtractor
from endpoint_scanner.ioc_normalizer import IOCNormalizer
from endpoint_scanner.models import Extension
from endpoint_scanner.permission_risk_score import score_extensions
from endpoint_scanner.scanner import EndpointScanner
from endpoint_scanner.syslog_sender import (
    SyslogEventSender,
    SyslogSendError,
)


DEFAULT_SYSLOG_HOST = "192.168.1.4"
DEFAULT_SYSLOG_PORT = 5514

ANALYSIS_REPORT_PATH = Path(
    "logs/latest_multifactor_analysis.json"
)


def apply_risk_scoring(
    extensions: list[Extension],
) -> list[Extension]:
    """
    Calculate permission-based risk scores.
    """

    scoring_result = score_extensions(
        extensions
    )

    if scoring_result is not None:
        if isinstance(
            scoring_result,
            Iterable,
        ):
            extensions = list(
                scoring_result
            )

        else:
            raise TypeError(
                "score_extensions() must return "
                "an iterable of extensions or None."
            )

    unscored_extensions = [
        extension.name
        or extension.extension_id
        for extension in extensions
        if (
            extension.risk_score is None
            or not str(
                extension.severity
            ).strip()
            or str(
                extension.severity
            ).strip().lower()
            == "unscored"
        )
    ]

    if unscored_extensions:
        raise RuntimeError(
            "Risk scoring did not produce "
            "results for: "
            + ", ".join(
                unscored_extensions
            )
        )

    return extensions


def display_extensions(
    extensions: list[Extension],
) -> None:
    installations = len(extensions)

    unique_extensions = len(
        {
            extension.extension_id
            for extension in extensions
        }
    )

    profiles = sorted(
        {
            extension.profile
            for extension in extensions
        }
    )

    print(
        "\n===== Chrome Extension Inventory ====="
    )
    print(
        f"Profiles scanned        : "
        f"{len(profiles)}"
    )
    print(
        f"Extension installations : "
        f"{installations}"
    )
    print(
        f"Unique extension IDs    : "
        f"{unique_extensions}"
    )

    for extension in extensions:
        findings = extension.findings or []

        print("\n" + "=" * 70)
        print(
            f"Profile               : "
            f"{extension.profile}"
        )
        print(
            f"Name                  : "
            f"{extension.name}"
        )
        print(
            f"Extension ID          : "
            f"{extension.extension_id}"
        )
        print(
            f"Version               : "
            f"{extension.version}"
        )
        print(
            f"Manifest Version      : "
            f"{extension.manifest_version}"
        )
        print(
            f"Permissions           : "
            f"{len(extension.permissions)}"
        )
        print(
            f"Host Permissions      : "
            f"{len(extension.host_permissions)}"
        )

        print(
            "\n----- Permission Risk Assessment -----"
        )
        print(
            f"Risk Score            : "
            f"{extension.risk_score}"
        )
        print(
            f"Severity              : "
            f"{extension.severity}"
        )
        print(
            f"Finding Count         : "
            f"{len(findings)}"
        )

        if findings:
            print("Findings              :")

            for finding in findings:
                category = finding.get(
                    "category",
                    "permission",
                )

                item = finding.get(
                    "item",
                    "unknown",
                )

                score = finding.get(
                    "score",
                    0,
                )

                reason = finding.get(
                    "reason",
                    "No explanation provided.",
                )

                print(
                    f"  - [{category}] "
                    f"{item} (+{score}): "
                    f"{reason}"
                )

        else:
            print(
                "Findings              : None"
            )

        print("=" * 70)


def get_syslog_configuration(
) -> tuple[str, int]:
    host = os.getenv(
        "WAZUH_SYSLOG_HOST",
        DEFAULT_SYSLOG_HOST,
    ).strip()

    port_text = os.getenv(
        "WAZUH_SYSLOG_PORT",
        str(DEFAULT_SYSLOG_PORT),
    ).strip()

    if not host:
        raise ValueError(
            "WAZUH_SYSLOG_HOST cannot be empty."
        )

    try:
        port = int(port_text)

    except ValueError as error:
        raise ValueError(
            "WAZUH_SYSLOG_PORT must be "
            "a valid integer."
        ) from error

    if not 1 <= port <= 65535:
        raise ValueError(
            "WAZUH_SYSLOG_PORT must be "
            "between 1 and 65535."
        )

    return host, port


def build_extension_path(
    extension: Extension,
) -> Path:
    """
    Resolve the installed Chrome extension directory.

    Chrome normally stores extensions at:

    %LOCALAPPDATA%\\Google\\Chrome\\User Data\\
    <Profile>\\Extensions\\<Extension ID>\\<Version>
    """

    local_app_data = os.getenv(
        "LOCALAPPDATA",
        "",
    ).strip()

    if not local_app_data:
        raise RuntimeError(
            "LOCALAPPDATA is not available."
        )

    extension_root = (
        Path(local_app_data)
        / "Google"
        / "Chrome"
        / "User Data"
        / str(extension.profile)
        / "Extensions"
        / str(extension.extension_id)
    )

    if not extension_root.is_dir():
        raise FileNotFoundError(
            "Extension root directory was "
            f"not found: {extension_root}"
        )

    version_text = str(
        extension.version
    ).strip()

    exact_path = (
        extension_root
        / version_text
    )

    if exact_path.is_dir():
        return exact_path

    candidates = sorted(
        [
            path
            for path in extension_root.iterdir()
            if path.is_dir()
            and (
                path.name == version_text
                or path.name.startswith(
                    version_text
                )
                or version_text.startswith(
                    path.name
                )
            )
        ],
        key=lambda path: path.name,
        reverse=True,
    )

    if candidates:
        return candidates[0]

    all_version_directories = sorted(
        [
            path
            for path in extension_root.iterdir()
            if path.is_dir()
        ],
        key=lambda path: path.name,
        reverse=True,
    )

    if len(all_version_directories) == 1:
        return all_version_directories[0]

    raise FileNotFoundError(
        "Could not match scanner version "
        f"'{version_text}' inside "
        f"{extension_root}"
    )


def build_analysis_key(
    extension: Extension,
) -> str:
    return (
        f"{extension.extension_id}:"
        f"{extension.version}"
    )


def analyze_extensions(
    extensions: list[Extension],
) -> dict[str, dict[str, Any]]:
    """
    Run IOC extraction, IOC normalization,
    VirusTotal enrichment and the existing
    ExtensionAnalyzer.

    Analysis is performed once per unique
    extension ID + version and reused across
    Chrome profiles.
    """

    if not os.getenv(
        "VT_API_KEY",
        "",
    ).strip():
        raise RuntimeError(
            "VT_API_KEY is not configured in "
            "this PowerShell session."
        )

    extractor = IOCExtractor()
    normalizer = IOCNormalizer()

    threat_intel_service = (
        ThreatIntelService(
            maximum_domains=1,
            maximum_urls=1,
            maximum_hashes=1,
            maximum_ips=0,
        )
    )

    analyzer = ExtensionAnalyzer()

    analysis_cache: dict[
        str,
        dict[str, Any],
    ] = {}

    print(
        "\n===== Multi-Factor Security Analysis ====="
    )

    for extension in extensions:
        cache_key = build_analysis_key(
            extension
        )

        if cache_key in analysis_cache:
            print(
                "\nReusing existing analysis for:"
            )
            print(
                f"  {extension.name}"
            )
            print(
                f"  Profile: "
                f"{extension.profile}"
            )

            profiles = analysis_cache[
                cache_key
            ].setdefault(
                "profiles",
                [],
            )

            if extension.profile not in profiles:
                profiles.append(
                    extension.profile
                )

            continue

        print("\n" + "=" * 70)
        print(
            f"Analyzing : "
            f"{extension.name}"
        )
        print(
            f"Profile   : "
            f"{extension.profile}"
        )
        print(
            f"ID        : "
            f"{extension.extension_id}"
        )
        print(
            f"Version   : "
            f"{extension.version}"
        )

        try:
            extension_path = (
                build_extension_path(
                    extension
                )
            )

            raw_report = extractor.extract(
                extension_path=extension_path,
                extension_id=(
                    extension.extension_id
                ),
            )

            # Add metadata required by the
            # normalizer and final analyzer.
            raw_report[
                "extension_name"
            ] = extension.name

            raw_report[
                "extension_version"
            ] = extension.version

            raw_report[
                "profile"
            ] = extension.profile

            normalized_report = (
                normalizer.normalize_report(
                    raw_report
                )
            )

            threat_intel_report = (
                threat_intel_service.enrich(
                    normalized_report
                )
            )

            assessment = analyzer.analyze(
                permission_score=int(
                    extension.risk_score
                    or 0
                ),
                normalized_report=(
                    normalized_report
                ),
                threat_intel_report=(
                    threat_intel_report
                ),
            )

            final_assessment = (
                assessment.get(
                    "final_assessment",
                    {},
                )
            )

            threat_result = (
                assessment.get(
                    "threat_intelligence_analysis",
                    {},
                )
            )

            static_result = (
                assessment.get(
                    "static_code_analysis",
                    {},
                )
            )

            analysis_cache[
                cache_key
            ] = {
                "analysis_status": "complete",
                "profiles": [
                    extension.profile
                ],
                "extension_path": str(
                    extension_path
                ),
                "ioc_summary": (
                    normalized_report.get(
                        "summary",
                        {},
                    )
                ),
                "threat_intel_summary": (
                    threat_intel_report.get(
                        "summary",
                        {},
                    )
                    if isinstance(
                        threat_intel_report,
                        dict,
                    )
                    else {}
                ),
                "assessment": assessment,
            }

            print(
                f"Permission Score : "
                f"{extension.risk_score}"
            )
            print(
                f"Threat Intel     : "
                f"{threat_result.get('score', 0)}"
            )
            print(
                f"Static Code      : "
                f"{static_result.get('score', 0)}"
            )
            print(
                f"Final Score      : "
                f"{final_assessment.get('final_score', 0)}"
            )
            print(
                f"Final Severity   : "
                f"{final_assessment.get('final_severity', 'unknown')}"
            )
            print(
                f"Recommendation   : "
                f"{final_assessment.get('recommendation', '')}"
            )

        except Exception as error:
            error_message = (
                f"{type(error).__name__}: "
                f"{error}"
            )

            print(
                "Analysis failed for this "
                "extension:"
            )
            print(
                error_message
            )

            analysis_cache[
                cache_key
            ] = {
                "analysis_status": "error",
                "analysis_error": (
                    error_message
                ),
                "profiles": [
                    extension.profile
                ],
                "assessment": {},
                "ioc_summary": {},
                "threat_intel_summary": {},
            }

    save_analysis_report(
        analysis_cache
    )

    return analysis_cache


def save_analysis_report(
    analysis_results: dict[
        str,
        dict[str, Any],
    ],
) -> None:
    ANALYSIS_REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = (
        ANALYSIS_REPORT_PATH.with_suffix(
            ".json.tmp"
        )
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            analysis_results,
            output_file,
            indent=4,
            ensure_ascii=False,
            default=str,
        )

    temporary_path.replace(
        ANALYSIS_REPORT_PATH
    )


def display_analysis_summary(
    analysis_results: dict[
        str,
        dict[str, Any],
    ],
) -> None:
    print(
        "\n===== Final Multi-Factor Summary ====="
    )

    for result in (
        analysis_results.values()
    ):
        status = result.get(
            "analysis_status",
            "unknown",
        )

        assessment = result.get(
            "assessment",
            {},
        )

        if not isinstance(
            assessment,
            dict,
        ):
            assessment = {}

        name = assessment.get(
            "extension_name",
            "Unknown Extension",
        )

        if status != "complete":
            print(
                f"{name} -> "
                f"Analysis {status}"
            )
            continue

        permission = assessment.get(
            "permission_analysis",
            {},
        )

        threat_intel = assessment.get(
            "threat_intelligence_analysis",
            {},
        )

        static_code = assessment.get(
            "static_code_analysis",
            {},
        )

        final = assessment.get(
            "final_assessment",
            {},
        )

        print(
            f"{name} -> "
            f"Permission "
            f"{permission.get('score', 0)}, "
            f"TI "
            f"{threat_intel.get('score', 0)}, "
            f"Static "
            f"{static_code.get('score', 0)}, "
            f"Final "
            f"{final.get('final_score', 0)} "
            f"({final.get('final_severity', 'unknown')})"
        )

    print(
        "\nDetailed analysis report:"
    )
    print(
        ANALYSIS_REPORT_PATH.resolve()
    )


def display_changes(
    changes: dict[str, list[dict]],
) -> None:
    print(
        "\n===== Inventory Changes ====="
    )
    print(
        f"Installed : "
        f"{len(changes.get('installed', []))}"
    )
    print(
        f"Updated   : "
        f"{len(changes.get('updated', []))}"
    )
    print(
        f"Removed   : "
        f"{len(changes.get('removed', []))}"
    )


def display_event_summary(
    scan_result: dict,
) -> None:
    print(
        "\n===== Event Summary ====="
    )
    print(
        f"Inventory events : "
        f"{scan_result['inventory_events']}"
    )
    print(
        f"Change events    : "
        f"{scan_result['change_events']}"
    )
    print(
        f"Total events     : "
        f"{scan_result['total_events']}"
    )


def main() -> None:
    print(
        "Starting Chrome extension scan..."
    )

    scanner = EndpointScanner()

    extensions = scanner.scan()

    if not extensions:
        print(
            "No Chrome extension installations "
            "were discovered."
        )
        return

    # 1. Permission scoring
    extensions = apply_risk_scoring(
        extensions
    )

    display_extensions(
        extensions
    )

    # 2. IOC extraction
    # 3. IOC normalization
    # 4. VirusTotal enrichment
    # 5. Threat-intelligence scoring
    # 6. Static-code scoring
    # 7. Final multi-factor assessment
    analysis_results = (
        analyze_extensions(
            extensions
        )
    )

    display_analysis_summary(
        analysis_results
    )

    event_writer = (
        JsonLinesEventWriter()
    )

    comparator = InventoryComparator(
        event_writer.snapshot_path
    )

    changes = comparator.compare(
        extensions
    )

    display_changes(
        changes
    )

    scan_result = (
        event_writer.prepare_scan(
            extensions=extensions,
            changes=changes,
            analysis_results=(
                analysis_results
            ),
        )
    )

    syslog_host, syslog_port = (
        get_syslog_configuration()
    )

    sender = SyslogEventSender(
        server=syslog_host,
        port=syslog_port,
    )

    print(
        "\n===== Syslog Delivery ====="
    )
    print(
        f"Destination : "
        f"{syslog_host}:{syslog_port}"
    )

    try:
        sent_count = (
            sender.send_events(
                scan_result["events"]
            )
        )

    except SyslogSendError as error:
        print(
            "\nSyslog delivery failed:"
        )
        print(error)

        try:
            fallback_path = (
                event_writer.write_fallback_spool(
                    scan_result
                )
            )

        except OSError as fallback_error:
            print(
                "\nFallback JSONL writing "
                "also failed:"
            )
            print(
                fallback_error
            )

        else:
            print(
                "\nEvents saved to "
                "fallback JSONL:"
            )
            print(
                fallback_path.resolve()
            )

        print(
            "\nThe inventory snapshot was not "
            "replaced. Change detection will "
            "retry these events during the next "
            "successful scan."
        )

        return

    event_writer.commit_snapshot(
        extensions=extensions,
        scan_result=scan_result,
    )

    print(
        f"\nSuccessfully sent "
        f"{sent_count} events through "
        f"TCP Syslog."
    )

    display_event_summary(
        scan_result
    )

    print(
        "\nLatest readable inventory:"
    )
    print(
        event_writer.snapshot_path.resolve()
    )


if __name__ == "__main__":
    main()
