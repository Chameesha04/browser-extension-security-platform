from endpoint_scanner.chrome import ChromeScanner
from endpoint_scanner.localization import LocalizationResolver
from endpoint_scanner.manifest import ManifestParser
from endpoint_scanner.models import Extension


class EndpointScanner:
    """Discover and collect metadata from Chrome extensions."""

    def __init__(self) -> None:
        self.chrome = ChromeScanner()
        self.manifest_parser = ManifestParser()
        self.localization = LocalizationResolver()

    def scan(self) -> list[Extension]:
        """
        Scan Chrome and return enriched Extension objects.

        Printing, saving and analysis are handled by other components.
        """
        extensions = self.chrome.get_extensions()

        for extension in extensions:
            self._populate_metadata(extension)

        return extensions

    def _populate_metadata(self, extension: Extension) -> None:
        metadata = self.manifest_parser.parse(extension.path)

        if metadata is None:
            extension.name = f"Unknown ({extension.extension_id})"
            return

        extension.default_locale = metadata["default_locale"]

        extension.name = self.localization.resolve(
            extension.path,
            metadata["name"],
            extension.default_locale,
        )

        extension.description = self.localization.resolve(
            extension.path,
            metadata["description"],
            extension.default_locale,
        )

        # Use the cleaner manifest version string instead of a folder
        # name such as 1.107.1_0 when it is available.
        if metadata["version"]:
            extension.version = metadata["version"]

        extension.manifest_version = metadata["manifest_version"]
        extension.permissions = metadata["permissions"]
        extension.host_permissions = metadata["host_permissions"]
        extension.optional_permissions = metadata[
            "optional_permissions"
        ]
        extension.background = metadata["background"]
        extension.content_scripts = metadata["content_scripts"]
        extension.action = metadata["action"]
        extension.icons = metadata["icons"]
        extension.homepage_url = metadata["homepage_url"]
        extension.update_url = metadata["update_url"]

