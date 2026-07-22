from pathlib import Path

from endpoint_scanner.browser_scanner import BrowserScanner


class ChromeScanner(BrowserScanner):

    def __init__(self):

        super().__init__(
            browser_name="Chrome",
            base_path=(
                Path.home()
                / "AppData"
                / "Local"
                / "Google"
                / "Chrome"
                / "User Data"
            ),
        )