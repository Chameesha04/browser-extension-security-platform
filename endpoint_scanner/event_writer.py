from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from endpoint_scanner.models import Extension


class JsonLinesEventWriter:
    """
    Build Chrome extension security events and maintain the latest
    readable inventory snapshot.

    JSONL spool files are now used only as a fallback when Syslog
    delivery fails.
    """

    CHANGE_EVENT_TYPES = {
        "installed": "extension_installed",
        "updated": "extension_updated",
        "removed": "extension_removed",
    }

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

        for change_type, event_type in (
            self.CHANGE_EVENT_TYPES.items()
        ):
            for change in changes.get(change_type, []):
                event = {
                    **self._base_event(
                        scan_id=scan_id,
                        timestamp=timestamp,
                        hostname=hostname,
                    ),
                    **change,
                }

                # Protect against comparator output that does not
                # explicitly contain an event_type field.
                event.setdefault("event_type", event_type)

                events.append(event)

        return events

    def prepare_scan(
        self,
        extensions: list[Extension],
        changes: dict[str, list[dict[str, Any]]],
    ) -> dict[str, Any]:
        """
        Create all inventory and change events without sending or
        writing them yet.
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

        return {
            "scan_id": scan_id,
            "timestamp": timestamp,
            "hostname": hostname,
            "inventory_event_records": inventory_events,
            "change_event_records": change_events,
            "events": all_events,
            "inventory_events": len(inventory_events),
            "change_events": len(change_events),
            "total_events": len(all_events),
        }

    def commit_snapshot(
        self,
        extensions: list[Extension],
        scan_result: dict[str, Any],
    ) -> None:
        """
        Save the latest inventory after successful Syslog delivery.
        """

        self._write_snapshot(
            extensions=extensions,
            inventory_events=scan_result[
                "inventory_event_records"
            ],
            scan_id=scan_result["scan_id"],
            timestamp=scan_result["timestamp"],
            hostname=scan_result["hostname"],
        )

    def write_fallback_spool(
        self,
        scan_result: dict[str, Any],
    ) -> Path:
        """
        Save undelivered events locally when Syslog is unavailable.
        """

        return self._write_spool_file(
            events=scan_result["events"],
            scan_id=scan_result["scan_id"],
            timestamp=scan_result["timestamp"],
        )

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
                        default=str,
                    )

                    log_file.write(json_line + "\n")

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
                    default=str,
                )

            temporary_snapshot.replace(
                self.snapshot_path
            )

        except Exception:
            if temporary_snapshot.exists():
                temporary_snapshot.unlink()

            raise