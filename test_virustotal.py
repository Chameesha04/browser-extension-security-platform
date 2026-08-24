from __future__ import annotations

import json
from pathlib import Path

from analysis_engine.virustotal_client import (
    VirusTotalClient,
    VirusTotalError,
)


REPORT_PATH = Path(
    "logs/latest_normalized_ioc_report.json"
)


def main() -> None:

    if not REPORT_PATH.is_file():
        print(
            "Normalized IOC report not found."
        )
        print(
            "Run test_ioc_normalizer.py first."
        )
        return

    with REPORT_PATH.open(
        "r",
        encoding="utf-8",
    ) as report_file:

        reports = json.load(
            report_file
        )

    if not reports:
        print("No extensions found.")
        return

    first_extension = reports[0]

    domains = (
        first_extension
        .get(
            "threat_intel_candidates",
            {}
        )
        .get(
            "domains",
            []
        )
    )

    if not domains:
        print(
            "No domain candidates available."
        )
        return

    domain = domains[0]

    print(
        "\n===== VirusTotal Test ====="
    )

    print(
        f"Extension : "
        f"{first_extension.get('extension_name')}"
    )

    print(
        f"Domain    : {domain}"
    )

    client = VirusTotalClient()

    try:
        result = client.lookup_domain(
            domain
        )

    except VirusTotalError as error:
        print(
            f"\nVirusTotal lookup failed:"
        )
        print(error)
        return

    print(
        "\n===== VirusTotal Result ====="
    )

    print(
        f"Status     : "
        f"{result['status']}"
    )

    print(
        f"Malicious  : "
        f"{result['malicious']}"
    )

    print(
        f"Suspicious : "
        f"{result['suspicious']}"
    )

    print(
        f"Harmless   : "
        f"{result['harmless']}"
    )

    print(
        f"Undetected : "
        f"{result['undetected']}"
    )

    print(
        f"Source     : "
        f"{result['source']}"
    )


if __name__ == "__main__":
    main()