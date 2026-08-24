from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from analysis_engine.threat_intel_service import (
    ThreatIntelService,
)


INPUT_PATH = Path(
    "logs/latest_normalized_ioc_report.json"
)

OUTPUT_PATH = Path(
    "logs/latest_all_threat_intel_report.json"
)


def main() -> None:

    if not INPUT_PATH.is_file():
        print(
            "Normalized IOC report not found."
        )
        print(
            "Run test_ioc_normalizer.py first."
        )
        return

    with INPUT_PATH.open(
        "r",
        encoding="utf-8",
    ) as input_file:

        reports = json.load(
            input_file
        )

    if not reports:
        print(
            "No normalized extension reports found."
        )
        return

    print(
        "\n=========================================="
    )
    print(
        "All Extension Threat Intelligence Scan"
    )
    print(
        "=========================================="
    )

    print(
        f"Extension installations found: "
        f"{len(reports)}"
    )

    service = ThreatIntelService(
        maximum_domains=1,
        maximum_urls=1,
        maximum_hashes=1,
        maximum_ips=0,
    )

    enriched_reports: list[
        dict[str, Any]
    ] = []

    # Store enrichment once for each unique
    # extension ID + version.
    enrichment_cache: dict[
        str,
        dict[str, Any],
    ] = {}

    for index, report in enumerate(
        reports,
        start=1,
    ):

        extension_name = str(
            report.get(
                "extension_name",
                "Unknown",
            )
        )

        extension_id = str(
            report.get(
                "extension_id",
                "",
            )
        )

        extension_version = str(
            report.get(
                "extension_version",
                "",
            )
        )

        profile = str(
            report.get(
                "profile",
                "",
            )
        )

        cache_key = str(
            report.get(
                "cache_key",
                "",
            )
        )

        if not cache_key:
            cache_key = (
                f"{extension_id}:"
                f"{extension_version}"
            )

        print(
            "\n"
            + "=" * 70
        )

        print(
            f"[{index}/{len(reports)}]"
        )

        print(
            f"Extension : "
            f"{extension_name}"
        )

        print(
            f"Profile   : "
            f"{profile or 'Unknown'}"
        )

        print(
            f"ID        : "
            f"{extension_id}"
        )

        print(
            f"Version   : "
            f"{extension_version}"
        )

        # -----------------------------------
        # Avoid duplicate VirusTotal work
        # -----------------------------------

        if cache_key in enrichment_cache:

            print(
                "Threat intel already checked "
                "for this extension/version."
            )

            print(
                "Reusing previous enrichment."
            )

            threat_intel = (
                enrichment_cache[
                    cache_key
                ]
            )

        else:

            threat_intel = (
                service.enrich(
                    report
                )
            )

            enrichment_cache[
                cache_key
            ] = threat_intel

        summary = threat_intel.get(
            "summary",
            {},
        )

        malicious_iocs = int(
            summary.get(
                "indicators_with_malicious_detections",
                0,
            )
        )

        suspicious_iocs = int(
            summary.get(
                "indicators_with_suspicious_detections",
                0,
            )
        )

        malicious_engines = int(
            summary.get(
                "total_malicious_engine_detections",
                0,
            )
        )

        suspicious_engines = int(
            summary.get(
                "total_suspicious_engine_detections",
                0,
            )
        )

        # -----------------------------------
        # Print summary ONCE
        # -----------------------------------

        print(
            "\nThreat Intelligence Summary"
        )

        print(
            f"Indicators checked : "
            f"{summary.get('indicators_checked', 0)}"
        )

        print(
            f"Reports found      : "
            f"{summary.get('reports_found', 0)}"
        )

        print(
            f"Reports not found  : "
            f"{summary.get('reports_not_found', 0)}"
        )

        print(
            f"Malicious IOCs     : "
            f"{malicious_iocs}"
        )

        print(
            f"Suspicious IOCs    : "
            f"{suspicious_iocs}"
        )

        print(
            f"Malicious engines  : "
            f"{malicious_engines}"
        )

        print(
            f"Suspicious engines : "
            f"{suspicious_engines}"
        )

        print(
            f"Lookup errors      : "
            f"{summary.get('lookup_errors', 0)}"
        )

        # -----------------------------------
        # Keep one record per installation
        # -----------------------------------

        combined_report = {
            "extension_name": (
                extension_name
            ),

            "extension_id": (
                extension_id
            ),

            "extension_version": (
                extension_version
            ),

            "profile": profile,

            "cache_key": cache_key,

            "ioc_summary": report.get(
                "summary",
                {},
            ),

            "threat_intelligence": (
                threat_intel
            ),
        }

        enriched_reports.append(
            combined_report
        )

    # ===================================
    # Overall UNIQUE enrichment summary
    # ===================================

    total_malicious_iocs = 0
    total_suspicious_iocs = 0

    total_malicious_engines = 0
    total_suspicious_engines = 0

    unique_extensions_with_malicious_evidence = 0
    unique_extensions_with_suspicious_evidence = 0

    for threat_intel in (
        enrichment_cache.values()
    ):

        summary = threat_intel.get(
            "summary",
            {},
        )

        malicious_iocs = int(
            summary.get(
                "indicators_with_malicious_detections",
                0,
            )
        )

        suspicious_iocs = int(
            summary.get(
                "indicators_with_suspicious_detections",
                0,
            )
        )

        malicious_engines = int(
            summary.get(
                "total_malicious_engine_detections",
                0,
            )
        )

        suspicious_engines = int(
            summary.get(
                "total_suspicious_engine_detections",
                0,
            )
        )

        total_malicious_iocs += (
            malicious_iocs
        )

        total_suspicious_iocs += (
            suspicious_iocs
        )

        total_malicious_engines += (
            malicious_engines
        )

        total_suspicious_engines += (
            suspicious_engines
        )

        if malicious_iocs > 0:
            unique_extensions_with_malicious_evidence += 1

        if suspicious_iocs > 0:
            unique_extensions_with_suspicious_evidence += 1

    # -----------------------------------
    # Save report
    # -----------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = OUTPUT_PATH.with_suffix(
        ".json.tmp"
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:

        json.dump(
            enriched_reports,
            output_file,
            indent=4,
            ensure_ascii=False,
        )

    temporary_path.replace(
        OUTPUT_PATH
    )

    # -----------------------------------
    # Final summary
    # -----------------------------------

    print(
        "\n"
        + "=" * 70
    )

    print(
        "ALL EXTENSION THREAT INTELLIGENCE COMPLETED"
    )

    print(
        "=" * 70
    )

    print(
        f"Installations processed : "
        f"{len(enriched_reports)}"
    )

    print(
        f"Unique extension/version: "
        f"{len(enrichment_cache)}"
    )

    print(
        f"Malicious IOC findings  : "
        f"{total_malicious_iocs}"
    )

    print(
        f"Suspicious IOC findings : "
        f"{total_suspicious_iocs}"
    )

    print(
        f"Malicious engines total : "
        f"{total_malicious_engines}"
    )

    print(
        f"Suspicious engines total: "
        f"{total_suspicious_engines}"
    )

    print(
        f"Extensions with malicious evidence  : "
        f"{unique_extensions_with_malicious_evidence}"
    )

    print(
        f"Extensions with suspicious evidence : "
        f"{unique_extensions_with_suspicious_evidence}"
    )

    print(
        f"\nReport saved to:\n"
        f"{OUTPUT_PATH.resolve()}"
    )


if __name__ == "__main__":
    main()