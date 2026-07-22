import json
from pathlib import Path
from typing import Any

from endpoint_scanner.models import Extension


class InventoryComparator:
    """Compare the current Chrome inventory with the previous snapshot."""

    def __init__(self, snapshot_path: Path) -> None:
        self.snapshot_path = snapshot_path

    @staticmethod
    def _extension_key(
        profile: str,
        extension_id: str,
    ) -> tuple[str, str]:
        """
        Use both profile and extension ID because the same extension
        may be installed in more than one Chrome profile.
        """
        return profile, extension_id

    def _load_previous_inventory(
        self,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        if not self.snapshot_path.is_file():
            return {}

        try:
            with self.snapshot_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                snapshot = json.load(file)

        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
        ):
            return {}

        previous_inventory = {}

        for extension in snapshot.get("extensions", []):
            profile = extension.get("profile", "")
            extension_id = extension.get("extension_id", "")

            if not profile or not extension_id:
                continue

            key = self._extension_key(
                profile,
                extension_id,
            )

            previous_inventory[key] = extension

        return previous_inventory

    def compare(
        self,
        current_extensions: list[Extension],
    ) -> dict[str, list[dict[str, Any]]]:
        previous = self._load_previous_inventory()

        current = {
            self._extension_key(
                extension.profile,
                extension.extension_id,
            ): extension
            for extension in current_extensions
        }

        installed = []
        updated = []
        removed = []

        # Newly installed and updated extensions
        for key, extension in current.items():
            previous_extension = previous.get(key)

            if previous_extension is None:
                installed.append(
                    {
                        "event_type": "extension_installed",
                        "profile": extension.profile,
                        "extension_id": extension.extension_id,
                        "extension_name": extension.name,
                        "extension_version": extension.version,
                    }
                )

                continue

            old_version = previous_extension.get(
                "extension_version",
                "",
            )

            if old_version != extension.version:
                updated.append(
                    {
                        "event_type": "extension_updated",
                        "profile": extension.profile,
                        "extension_id": extension.extension_id,
                        "extension_name": extension.name,
                        "old_version": old_version,
                        "new_version": extension.version,
                    }
                )

        # Removed extensions
        for key, previous_extension in previous.items():
            if key in current:
                continue

            removed.append(
                {
                    "event_type": "extension_removed",
                    "profile": previous_extension.get(
                        "profile",
                        "",
                    ),
                    "extension_id": previous_extension.get(
                        "extension_id",
                        "",
                    ),
                    "extension_name": previous_extension.get(
                        "extension_name",
                        "Unknown extension",
                    ),
                    "last_known_version": previous_extension.get(
                        "extension_version",
                        "",
                    ),
                }
            )

        return {
            "installed": installed,
            "updated": updated,
            "removed": removed,
        }