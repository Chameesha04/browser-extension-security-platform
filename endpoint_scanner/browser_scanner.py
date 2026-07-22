from pathlib import Path
from endpoint_scanner.models import Extension


class BrowserScanner:

    def __init__(self, browser_name: str, base_path: Path):
        self.browser_name = browser_name
        self.base_path = base_path

    def browser_exists(self):
        """Check whether the browser data directory exists."""
        return self.base_path.exists()

    def get_browser_path(self):
        """Return the browser data directory."""
        return self.base_path

    def get_profiles(self):
        """Return all browser profiles."""

        profiles = []

        if not self.browser_exists():
            return profiles

        for folder in self.base_path.iterdir():

            if not folder.is_dir():
                continue

            if folder.name == "Default":
                profiles.append(folder)

            elif folder.name.startswith("Profile"):
                profiles.append(folder)

        return profiles

    def get_extensions(self):
        """Return all installed extensions."""

        extensions = []

        for profile in self.get_profiles():

            extensions_path = profile / "Extensions"

            if not extensions_path.exists():
                continue

            for extension_folder in extensions_path.iterdir():

                if not extension_folder.is_dir():
                    continue

                versions = [
                    folder
                    for folder in extension_folder.iterdir()
                    if folder.is_dir()
                ]

                if not versions:
                    continue

                latest_version = sorted(versions)[-1]

                extension = Extension(
                    browser=self.browser_name,
                    profile=profile.name,
                    extension_id=extension_folder.name,
                    version=latest_version.name,
                    path=latest_version,
                )

                extensions.append(extension)

        return extensions