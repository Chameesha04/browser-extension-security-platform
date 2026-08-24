import json
from pathlib import Path

from analysis_engine.threat_intel_scorer import (
    ThreatIntelScorer,
)


INPUT_PATH = Path(
    "logs/latest_all_threat_intel_report.json"
)


def main():

    with INPUT_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:

        reports = json.load(file)

    scorer = ThreatIntelScorer()

    seen = set()

    print(
        "\n===== Threat Intelligence Scores ====="
    )

    for report in reports:

        cache_key = report.get(
            "cache_key",
            "",
        )

        if cache_key in seen:
            continue

        seen.add(cache_key)

        threat_intel = report.get(
            "threat_intelligence",
            {},
        )

        result = scorer.score(
            threat_intel
        )

        print(
            "\n"
            + "=" * 65
        )

        print(
            f"Extension : "
            f"{report.get('extension_name')}"
        )

        print(
            f"Score      : "
            f"{result['score']} / 100"
        )

        print(
            f"Severity   : "
            f"{result['severity']}"
        )

        print(
            f"Confidence : "
            f"{result['confidence']}"
        )

        print(
            f"Flagged IOCs: "
            f"{result['flagged_indicators']}"
        )

        print(
            f"Malicious engines: "
            f"{result['total_malicious_engine_detections']}"
        )


if __name__ == "__main__":
    main()