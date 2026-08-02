from endpoint_scanner.event_writer import JsonLinesEventWriter
from endpoint_scanner.inventory_comparator import InventoryComparator
from endpoint_scanner.models import Extension
from endpoint_scanner.scanner import EndpointScanner
from endpoint_scanner.risk_scorer import (
    score_extensions,
    score_results,
)  


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
        print(f"Risk Score          : {extension.risk_score}")
        print(f"Severity            : {extension.severity}")

        if extension.findings:
            print("Findings            :")
            for finding in extension.findings:
                print(
                    f"  - [{finding['category']}] "
                    f"{finding['item']} "
                    f"(+{finding['score']}): "
                    f"{finding['reason']}"
            )
        else:
            print("Findings            : None")

        print("=" * 60)


def main() -> None:
    print("Starting Chrome extension scan...")

    scanner = EndpointScanner()
    extensions = scanner.scan()

    # Add risk scores to Extension objects
    score_extensions(extensions)

    display_extensions(extensions)

    event_writer = JsonLinesEventWriter()

    # Compare with the previous readable snapshot before replacing it.
    comparator = InventoryComparator(
        event_writer.snapshot_path
    )

    changes = comparator.compare(extensions)

    result = event_writer.write_scan(
        extensions=extensions,
        changes=changes,
    )

    print("\n===== Inventory Changes =====")
    print(f"Installed : {len(changes['installed'])}")
    print(f"Updated   : {len(changes['updated'])}")
    print(f"Removed   : {len(changes['removed'])}")

    print("\n===== Wazuh Event Output =====")
    print(
        f"Inventory events : "
        f"{result['inventory_events']}"
    )
    print(
        f"Change events    : "
        f"{result['change_events']}"
    )
    print(
        f"Total events     : "
        f"{result['total_events']}"
    )

    print("\nCompleted Wazuh spool file:")
    print(result["spool_file"].resolve())

    print("\nLatest readable inventory:")
    print(event_writer.snapshot_path.resolve())
    score_results()
    import json



if __name__ == "__main__":
    main()