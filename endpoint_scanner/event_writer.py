import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from endpoint_scanner.models import Extension


class JsonLinesEventWriter:
    """
    Write each completed scan to a separate JSONL spool file.

    A temporary file is used while writing. It is renamed to .jsonl
    only after all events have been written successfully. This prevents
    Wazuh from reading an incomplete scan file.
    """

    def __init__(
        self,
        spool_directory: Path | None = None,
        snapshot_path: Path | None = None,
    ) -> None:
        self.spool_directory = spool_directory or Path(
            "logs/wazuh_spool"
        )

        self.snapshot_path = snapshot_path or Path(
            "logs/latest_chrome_inventory.json"
        )

    @staticmethod
    def _base_event(
        scan_id: str,
        timestamp: str,
        hostname: str,
    ) -> dict[str, Any]:
        return {
            "integration": "chrome_extension_security",
            "scan_id": scan_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "browser": "Chrome",
        }

    def _create_inventory_event(
        self,
        extension: Extension,
        scan_id: str,
        timestamp: str,
        hostname: str,
    ) -> dict[str, Any]:
        return {
            **self._base_event(
                scan_id=scan_id,
                timestamp=timestamp,
                hostname=hostname,
            ),
            "event_type": "extension_inventory",
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

    def _create_change_events(
        self,
        changes: dict[str, list[dict[str, Any]]],
        scan_id: str,
        timestamp: str,
        hostname: str,
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        for change_type in (
            "installed",
            "updated",
            "removed",
        ):
            for change in changes.get(change_type, []):
                events.append(
                    {
                        **self._base_event(
                            scan_id=scan_id,
                            timestamp=timestamp,
                            hostname=hostname,
                        ),
                        **change,
                    }
                )

        return events

    def _write_spool_file(
        self,
        events: list[dict[str, Any]],
        scan_id: str,
        timestamp: str,
    ) -> Path:
        self.spool_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        filename_timestamp = (
            timestamp
            .replace("-", "")
            .replace(":", "")
            .replace("+00:00", "Z")
            .replace(".", "_")
        )

        final_path = self.spool_directory / (
            f"scan_{filename_timestamp}_{scan_id[:8]}.jsonl"
        )

        temporary_path = self.spool_directory / (
            f".scan_{scan_id}.tmp"
        )

        try:
            with temporary_path.open(
                "w",
                encoding="utf-8",
                newline="\n",
            ) as log_file:
                for event in events:
                    json_line = json.dumps(
                        event,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )

                    log_file.write(json_line + "\n")

            # Rename only after writing and closing the complete file.
            temporary_path.replace(final_path)

        except Exception:
            if temporary_path.exists():
                temporary_path.unlink()

            raise

        return final_path

    def _write_snapshot(
        self,
        extensions: list[Extension],
        inventory_events: list[dict[str, Any]],
        scan_id: str,
        timestamp: str,
        hostname: str,
    ) -> None:
        self.snapshot_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        profiles = {
            extension.profile
            for extension in extensions
        }

        unique_ids = {
            extension.extension_id
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
            "extensions": inventory_events,
        }

        temporary_snapshot = self.snapshot_path.with_suffix(
            ".json.tmp"
        )

        try:
            with temporary_snapshot.open(
                "w",
                encoding="utf-8",
            ) as snapshot_file:
                json.dump(
                    readable_snapshot,
                    snapshot_file,
                    indent=4,
                    ensure_ascii=False,
                )

            temporary_snapshot.replace(
                self.snapshot_path
            )

        except Exception:
            if temporary_snapshot.exists():
                temporary_snapshot.unlink()

            raise

    def write_scan(
        self,
        extensions: list[Extension],
        changes: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """
        Write inventory and change events into one completed spool file.

        The latest readable inventory snapshot is also updated.
        """

        scan_id = str(uuid4())
        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        hostname = socket.gethostname()

        change_events = self._create_change_events(
            changes=changes,
            scan_id=scan_id,
            timestamp=timestamp,
            hostname=hostname,
        )

        inventory_events = [
            self._create_inventory_event(
                extension=extension,
                scan_id=scan_id,
                timestamp=timestamp,
                hostname=hostname,
            )
            for extension in extensions
        ]

        all_events = change_events + inventory_events

        spool_file = self._write_spool_file(
            events=all_events,
            scan_id=scan_id,
            timestamp=timestamp,
        )

        self._write_snapshot(
            extensions=extensions,
            inventory_events=inventory_events,
            scan_id=scan_id,
            timestamp=timestamp,
            hostname=hostname,
        )

        return {
            "scan_id": scan_id,
            "spool_file": spool_file,
            "inventory_events": len(inventory_events),
            "change_events": len(change_events),
            "total_events": len(all_events),
        }