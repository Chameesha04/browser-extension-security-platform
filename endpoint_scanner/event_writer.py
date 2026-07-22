import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from endpoint_scanner.models import Extension


class JsonLinesEventWriter:
    """
    Writes two files:

    1. JSONL event history for Wazuh.
    2. A readable JSON snapshot of the latest scan.
    """

    def __init__(
        self,
        output_path: Path | None = None,
        snapshot_path: Path | None = None,
    ) -> None:
        self.output_path = output_path or Path(
            "logs/chrome_extension_events.jsonl"
        )

        self.snapshot_path = snapshot_path or Path(
            "logs/latest_chrome_inventory.json"
        )

    def write_change_events(
        self,
        changes: dict[str, list[dict]],
    ) -> int:
        """Append installed, updated and removed events for Wazuh."""

        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        timestamp = datetime.now(timezone.utc).isoformat()
        hostname = socket.gethostname()
        scan_id = str(uuid4())

        events_written = 0

        with self.output_path.open(
            "a",
            encoding="utf-8",
        ) as log_file:

            for change_type in (
                "installed",
                "updated",
                "removed",
            ):
                for change in changes.get(change_type, []):
                    event = {
                        "integration": (
                            "chrome_extension_security"
                        ),
                        "scan_id": scan_id,
                        "timestamp": timestamp,
                        "hostname": hostname,
                        "browser": "Chrome",
                        **change,
                    }

                    log_file.write(
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                    events_written += 1

        return events_written

    def _create_event(
        self,
        extension: Extension,
        scan_id: str,
        timestamp: str,
        hostname: str,
    ) -> dict:
        """Create one structured Chrome extension event."""

        return {
            "integration": "chrome_extension_security",
            "event_type": "extension_inventory",
            "scan_id": scan_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "browser": "Chrome",
            "profile": extension.profile,
            "extension_id": extension.extension_id,
            "extension_name": extension.name,
            "extension_version": extension.version,
            "manifest_version": extension.manifest_version,
            "permissions": extension.permissions,
            "host_permissions": extension.host_permissions,
            "risk_score": extension.risk_score,
            "severity": extension.severity,
        }

    def write_scan(
        self,
        extensions: list[Extension],
    ) -> int:
        """
        Append Wazuh events and overwrite the latest readable snapshot.
        """

        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.snapshot_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        scan_id = str(uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        hostname = socket.gethostname()

        events = [
            self._create_event(
                extension=extension,
                scan_id=scan_id,
                timestamp=timestamp,
                hostname=hostname,
            )
            for extension in extensions
        ]

        # Wazuh-compatible event history:
        # one JSON object per line.
        with self.output_path.open(
            "a",
            encoding="utf-8",
        ) as log_file:
            for event in events:
                log_file.write(
                    json.dumps(
                        event,
                        ensure_ascii=False,
                    )
                    + "\n"
                )

        unique_ids = {
            extension.extension_id
            for extension in extensions
        }

        profiles = {
            extension.profile
            for extension in extensions
        }

        readable_snapshot = {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "browser": "Chrome",
            "summary": {
                "profiles_scanned": len(profiles),
                "extension_installations": len(extensions),
                "unique_extension_ids": len(unique_ids),
            },
            "extensions": events,
        }

        # Human-readable latest scan.
        # This file is overwritten during every scan.
        with self.snapshot_path.open(
            "w",
            encoding="utf-8",
        ) as snapshot_file:
            json.dump(
                readable_snapshot,
                snapshot_file,
                indent=4,
                ensure_ascii=False,
            )

        return len(events)