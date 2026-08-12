from __future__ import annotations

import json
from pathlib import Path

from endpoint_scanner.ioc_normalizer import (
    IOCNormalizer,
)


INPUT_PATH = Path(
    "logs/latest_ioc_report.json"
)

OUTPUT_PATH = Path(
    "logs/latest_normalized_ioc_report.json"
)


def main() -> None:
    if not INPUT_PATH.is_file():
        raise FileNotFoundError(
            "Raw IOC report was not found. "
            "Run test_ioc_extractor.py first."
        )

    with INPUT_PATH.open(
        "r",
        encoding="utf-8",
    ) as input_file:
        raw_reports = json.load(
            input_file
        )

    normalizer = IOCNormalizer()

    normalized_reports = []

    print(
        "Starting IOC normalization..."
    )

    for raw_report in raw_reports:
        normalized = (
            normalizer.normalize_report(
                raw_report
            )
        )

        normalized_reports.append(
            normalized
        )

        summary = normalized["summary"]

        print("\n" + "=" * 70)
        print(
            f"Extension : "
            f"{normalized['extension_name']}"
        )
        print(
            f"ID        : "
            f"{normalized['extension_id']}"
        )

        print(
            f"URL candidates       : "
            f"{summary['url_candidates']}"
        )

        print(
            f"Domain candidates    : "
            f"{summary['domain_candidates']}"
        )

        print(
            f"Public IP candidates : "
            f"{summary['public_ip_candidates']}"
        )

        print(
            f"Hash candidates      : "
            f"{summary['hash_candidates']}"
        )

        print(
            f"High code signals    : "
            f"{summary['high_confidence_code_signals']}"
        )

        print(
            f"Medium code signals  : "
            f"{summary['medium_confidence_code_signals']}"
        )

        print(
            f"Low code signals     : "
            f"{summary['low_confidence_code_signals']}"
        )

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
            normalized_reports,
            output_file,
            indent=4,
            ensure_ascii=False,
        )

    temporary_path.replace(
        OUTPUT_PATH
    )

    print(
        "\nIOC normalization completed."
    )

    print(
        f"Extensions processed: "
        f"{len(normalized_reports)}"
    )

    print(
        f"Report saved to: "
        f"{OUTPUT_PATH.resolve()}"
    )


if __name__ == "__main__":
    main()