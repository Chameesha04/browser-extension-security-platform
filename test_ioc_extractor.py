from __future__ import annotations

import json
from pathlib import Path

from endpoint_scanner.ioc_extractor import (
    IOCExtractionError,
    IOCExtractor,
)
from endpoint_scanner.scanner import EndpointScanner


def main() -> None:
    print("Starting IOC extraction test...")

    scanner = EndpointScanner()
    extensions = scanner.scan()

    extractor = IOCExtractor()

    reports: list[dict] = []

    for extension in extensions:
        print("\n" + "=" * 70)
        print(f"Extension : {extension.name}")
        print(f"Profile   : {extension.profile}")
        print(f"ID        : {extension.extension_id}")

        try:
            report = extractor.extract(
                extension_path=extension.path,
                extension_id=extension.extension_id,
            )

        except IOCExtractionError as error:
            print(f"IOC extraction failed: {error}")
            continue

        report["extension_name"] = (
            extension.name
        )

        report["profile"] = (
            extension.profile
        )

        reports.append(report)

        summary = report["summary"]

        print(
            f"Hashes             : "
            f"{summary['hashes_calculated']}"
        )

        print(
            f"URLs               : "
            f"{summary['url_count']}"
        )

        print(
            f"Domains            : "
            f"{summary['domain_count']}"
        )

        print(
            f"IP addresses       : "
            f"{summary['ip_address_count']}"
        )

        print(
            f"API endpoints      : "
            f"{summary['api_endpoint_count']}"
        )

        print(
            f"Obfuscation signals: "
            f"{summary['suspicious_indicator_count']}"
        )

    output_path = Path(
        "logs/latest_ioc_report.json"
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = output_path.with_suffix(
        ".json.tmp"
    )

    with temporary_path.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        json.dump(
            reports,
            output_file,
            indent=4,
            ensure_ascii=False,
        )

    temporary_path.replace(output_path)

    print("\nIOC extraction completed.")
    print(f"Extensions processed: {len(reports)}")
    print(f"Report saved to: {output_path.resolve()}")


if __name__ == "__main__":
    main()