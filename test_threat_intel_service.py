from __future__ import annotations

import json
from pathlib import Path

from analysis_engine.threat_intel_service import (
    ThreatIntelService,
)


INPUT_PATH = Path(
    "logs/latest_normalized_ioc_report.json"
)

OUTPUT_PATH = Path(
    "logs/latest_threat_intel_report.json"
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
            "No normalized extension "
            "reports found."
        )

        return

    # IMPORTANT:
    # Test only ONE extension first.
    report = reports[0]

    print(
        "\n====================================="
    )

    print(
        "Threat Intelligence Enrichment Test"
    )

    print(
        "====================================="
    )

    print(
        f"Extension : "
        f"{report.get('extension_name', '')}"
    )

    print(
        f"ID        : "
        f"{report.get('extension_id', '')}"
    )

    print()

    service = ThreatIntelService(
        maximum_domains=1,
        maximum_urls=1,
        maximum_hashes=1,
        maximum_ips=0,
    )

    enriched_report = service.enrich(
        report
    )

    summary = enriched_report[
        "summary"
    ]

    print(
        "\n========== Summary =========="
    )

    print(
        f"Indicators checked : "
        f"{summary['indicators_checked']}"
    )

    print(
        f"Reports found      : "
        f"{summary['reports_found']}"
    )

    print(
        f"Reports not found  : "
        f"{summary['reports_not_found']}"
    )

    print(
        f"Malicious IOCs     : "
        f"{summary['indicators_with_malicious_detections']}"
    )

    print(
        f"Suspicious IOCs    : "
        f"{summary['indicators_with_suspicious_detections']}"
    )

    print(
        f"Malicious engines  : "
        f"{summary['total_malicious_engine_detections']}"
    )

    print(
        f"Suspicious engines : "
        f"{summary['total_suspicious_engine_detections']}"
    )

    print(
        f"Lookup errors      : "
        f"{summary['lookup_errors']}"
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
    ) as output_file:

        json.dump(
            enriched_report,
            output_file,
            indent=4,
            ensure_ascii=False,
        )

    print(
        "\nThreat intelligence "
        "enrichment completed."
    )

    print(
        f"Report saved to: "
        f"{OUTPUT_PATH.resolve()}"
    )


if __name__ == "__main__":
    main()