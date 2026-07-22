from endpoint_scanner.event_writer import JsonLinesEventWriter
from endpoint_scanner.inventory_comparator import InventoryComparator
from endpoint_scanner.models import Extension
from endpoint_scanner.scanner import EndpointScanner


def display_extensions(
    extensions: list[Extension],
) -> None:
    """Display a readable summary of discovered Chrome extensions."""

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


def main() -> None:
    """Run the Chrome extension scanning workflow."""

    print("Starting Chrome extension scan...")

    scanner = EndpointScanner()
    extensions = scanner.scan()

    display_extensions(extensions)

    event_writer = JsonLinesEventWriter()

    # Compare against the previous snapshot before replacing it.
    comparator = InventoryComparator(
        event_writer.snapshot_path
    )

    changes = comparator.compare(extensions)

    # Write installed, updated and removed events first.
    change_event_count = event_writer.write_change_events(
        changes
    )

    # Write full inventory events and replace the latest snapshot.
    inventory_event_count = event_writer.write_scan(
        extensions
    )

    print("\n===== Inventory Changes =====")
    print(f"Installed : {len(changes['installed'])}")
    print(f"Updated   : {len(changes['updated'])}")
    print(f"Removed   : {len(changes['removed'])}")

    print(
        f"\n{inventory_event_count} inventory events written."
    )

    print(
        f"{change_event_count} change events written."
    )

    print("\nWazuh JSONL file:")
    print(event_writer.output_path.resolve())

    print("\nLatest readable inventory:")
    print(event_writer.snapshot_path.resolve())


if __name__ == "__main__":
    main()