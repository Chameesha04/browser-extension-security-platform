import json
from pathlib import Path
from typing import Any


class ManifestParser:
    """Read security-relevant metadata from manifest.json."""

    def parse(self, extension_path: Path) -> dict[str, Any] | None:
        manifest_path = extension_path / "manifest.json"

        if not manifest_path.is_file():
            return None

        try:
            # utf-8-sig also handles manifests that contain a UTF-8 BOM.
            with manifest_path.open("r", encoding="utf-8-sig") as file:
                manifest = json.load(file)

        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            print(f"Could not parse manifest: {manifest_path}")
            print(f"Reason: {error}")
            return None

        # Manifest V3 normally uses "action".
        # Manifest V2 may use browser_action or page_action.
        action = (
            manifest.get("action")
            or manifest.get("browser_action")
            or manifest.get("page_action")
            or {}
        )

        return {
            "name": manifest.get("name", ""),
            "description": manifest.get("description", ""),
            "version": manifest.get("version", ""),
            "default_locale": manifest.get("default_locale", ""),
            "manifest_version": manifest.get("manifest_version", 0),
            "permissions": manifest.get("permissions", []),
            "host_permissions": manifest.get("host_permissions", []),
            "optional_permissions": manifest.get(
                "optional_permissions",
                [],
            ),
            "background": manifest.get("background", {}),
            "content_scripts": manifest.get("content_scripts", []),
            "action": action,
            "icons": manifest.get("icons", {}),
            "homepage_url": manifest.get("homepage_url", ""),
            "update_url": manifest.get("update_url", ""),
        }