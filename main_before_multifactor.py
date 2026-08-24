from __future__ import annotations

import os
from typing import Iterable

from endpoint_scanner.event_writer import JsonLinesEventWriter
from endpoint_scanner.inventory_comparator import InventoryComparator
from endpoint_scanner.models import Extension
from endpoint_scanner.permission_risk_score import score_extensions
from endpoint_scanner.scanner import EndpointScanner
from endpoint_scanner.syslog_sender import (
    SyslogEventSender,
    SyslogSendError,
)


# This is only the fallback address.
# The WAZUH_SYSLOG_HOST environment variable overrides it.
DEFAULT_SYSLOG_HOST = "192.168.1.4"
DEFAULT_SYSLOG_PORT = 5514


def apply_risk_scoring(
    extensions: list[Extension],
) -> list[Extension]:
    """
    Calculate permission-based risk scores.

    Supports scoring functions that either:
    1. Modify the supplied list in place and return None, or
    2. Return the scored extensions.
    """

    scoring_result = score_extensions(extensions)

    if scoring_result is not None:
        if isinstance(scoring_result, Iterable):
            extensions = list(scoring_result)
        else:
            raise TypeError(
                "score_extensions() must return an iterable "
                "of extensions or None."
            )

    unscored_extensions = [
        extension.name or extension.extension_id
        for extension in extensions
        if (
            extension.risk_score is None
            or not str(extension.severity).strip()
            or str(extension.severity).strip().lower()
            == "unscored"
        )
    ]

    if unscored_extensions:
        raise RuntimeError(
            "Risk scoring did not produce results for: "
            + ", ".join(unscored_extensions)
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

    print("\n===== Chrome Extension Inventory =====")
    print(f"Profiles scanned        : {len(profiles)}")
    print(f"Extension installations : {installations}")
    print(f"Unique extension IDs    : {unique_extensions}")

    for extension in extensions:
        findings = extension.findings or []

        print("\n" + "=" * 70)
        print(f"Profile               : {extension.profile}")
        print(f"Name                  : {extension.name}")
        print(f"Extension ID          : {extension.extension_id}")
        print(f"Version               : {extension.version}")
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

        print("\n----- Permission Risk Assessment -----")
        print(f"Risk Score            : {extension.risk_score}")
        print(f"Severity              : {extension.severity}")
        print(f"Finding Count         : {len(findings)}")

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
                    f"  - [{category}] {item} "
                    f"(+{score}): {reason}"
                )
        else:
            print("Findings              : None")

        print("=" * 70)


def get_syslog_configuration() -> tuple[str, int]:
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
            "WAZUH_SYSLOG_PORT must be a valid integer."
        ) from error

    if not 1 <= port <= 65535:
        raise ValueError(
            "WAZUH_SYSLOG_PORT must be between "
            "1 and 65535."
        )

    return host, port


def display_changes(
    changes: dict[str, list[dict]],
) -> None:
    print("\n===== Inventory Changes =====")
    print(f"Installed : {len(changes.get('installed', []))}")
    print(f"Updated   : {len(changes.get('updated', []))}")
    print(f"Removed   : {len(changes.get('removed', []))}")


def display_event_summary(
    scan_result: dict,
) -> None:
    print("\n===== Event Summary =====")
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
    print("Starting Chrome extension scan...")

    scanner = EndpointScanner()
    extensions = scanner.scan()

    if not extensions:
        print(
            "No Chrome extension installations "
            "were discovered."
        )
        return

    # Risk scoring must happen before:
    # comparison, event generation and Syslog delivery.
    extensions = apply_risk_scoring(extensions)

    display_extensions(extensions)

    event_writer = JsonLinesEventWriter()

    # Compare against the previous successfully delivered inventory.
    comparator = InventoryComparator(
        event_writer.snapshot_path
    )

    changes = comparator.compare(extensions)

    display_changes(changes)

    scan_result = event_writer.prepare_scan(
        extensions=extensions,
        changes=changes,
    )

    syslog_host, syslog_port = (
        get_syslog_configuration()
    )

    sender = SyslogEventSender(
        server=syslog_host,
        port=syslog_port,
    )

    print("\n===== Syslog Delivery =====")
    print(f"Destination : {syslog_host}:{syslog_port}")

    try:
        sent_count = sender.send_events(
            scan_result["events"]
        )

    except SyslogSendError as error:
        print("\nSyslog delivery failed:")
        print(error)

        try:
            fallback_path = (
                event_writer.write_fallback_spool(
                    scan_result
                )
            )

        except OSError as fallback_error:
            print(
                "\nFallback JSONL writing also failed:"
            )
            print(fallback_error)

        else:
            print(
                "\nEvents saved to fallback JSONL:"
            )
            print(fallback_path.resolve())

        print(
            "\nThe inventory snapshot was not replaced. "
            "Change detection will retry these events "
            "during the next successful scan."
        )

        return

    # Only replace the comparison snapshot after all events
    # have been delivered successfully.
    event_writer.commit_snapshot(
        extensions=extensions,
        scan_result=scan_result,
    )

    print(
        f"\nSuccessfully sent {sent_count} "
        f"events through TCP Syslog."
    )

    display_event_summary(scan_result)

    print("\nLatest readable inventory:")
    print(event_writer.snapshot_path.resolve())


if __name__ == "__main__":
    main()