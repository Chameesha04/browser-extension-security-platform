from __future__ import annotations

import os

from endpoint_scanner.event_writer import JsonLinesEventWriter
from endpoint_scanner.inventory_comparator import (
    InventoryComparator,
)
from endpoint_scanner.models import Extension
from endpoint_scanner.scanner import EndpointScanner
from endpoint_scanner.syslog_sender import (
    SyslogEventSender,
    SyslogSendError,
)


DEFAULT_SYSLOG_HOST = "10.125.100.28"
DEFAULT_SYSLOG_PORT = 5514


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
        print("\n" + "=" * 60)
        print(f"Profile             : {extension.profile}")
        print(f"Name                : {extension.name}")
        print(f"Extension ID        : {extension.extension_id}")
        print(f"Version             : {extension.version}")

        print(
            f"Manifest Version    : "
            f"{extension.manifest_version}"
        )

        print(
            f"Permissions         : "
            f"{len(extension.permissions)}"
        )

        print(
            f"Host Permissions    : "
            f"{len(extension.host_permissions)}"
        )

        print("=" * 60)


def get_syslog_configuration() -> tuple[str, int]:
    host = os.getenv(
        "WAZUH_SYSLOG_HOST",
        DEFAULT_SYSLOG_HOST,
    ).strip()

    port_text = os.getenv(
        "WAZUH_SYSLOG_PORT",
        str(DEFAULT_SYSLOG_PORT),
    )

    try:
        port = int(port_text)

    except ValueError as error:
        raise ValueError(
            "WAZUH_SYSLOG_PORT must be a valid integer."
        ) from error

    if not host:
        raise ValueError(
            "WAZUH_SYSLOG_HOST cannot be empty."
        )

    if not 1 <= port <= 65535:
        raise ValueError(
            "WAZUH_SYSLOG_PORT must be between 1 and 65535."
        )

    return host, port


def main() -> None:
    print("Starting Chrome extension scan...")

    scanner = EndpointScanner()
    extensions = scanner.scan()

    display_extensions(extensions)

    event_writer = JsonLinesEventWriter()

    # Compare against the previous successfully delivered inventory.
    comparator = InventoryComparator(
        event_writer.snapshot_path
    )

    changes = comparator.compare(extensions)

    scan_result = event_writer.prepare_scan(
        extensions=extensions,
        changes=changes,
    )

    print("\n===== Inventory Changes =====")
    print(f"Installed : {len(changes['installed'])}")
    print(f"Updated   : {len(changes['updated'])}")
    print(f"Removed   : {len(changes['removed'])}")

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
        print("Syslog delivery failed:")
        print(error)

        try:
            fallback_path = (
                event_writer.write_fallback_spool(
                    scan_result
                )
            )

        except OSError as fallback_error:
            print("\nFallback JSONL writing also failed:")
            print(fallback_error)

        else:
            print("\nEvents saved to fallback JSONL:")
            print(fallback_path.resolve())

        print(
            "\nThe inventory snapshot was not replaced. "
            "Change detection will retry these changes "
            "during the next scan."
        )

        return

    event_writer.commit_snapshot(
        extensions=extensions,
        scan_result=scan_result,
    )

    print(
        f"Successfully sent {sent_count} "
        f"events through TCP Syslog."
    )

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

    print("\nLatest readable inventory:")
    print(event_writer.snapshot_path.resolve())


if __name__ == "__main__":
    main()