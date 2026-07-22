import json
import re
from pathlib import Path


class LocalizationResolver:
    """Resolve Chrome __MSG_key__ localization placeholders."""

    MESSAGE_PATTERN = re.compile(
        r"^__MSG_(.+)__$",
        re.IGNORECASE,
    )

    @staticmethod
    def _normalize_key(key: str) -> str:
        """
        Make keys comparable.

        Examples:
            APP_NAME -> appname
            appName  -> appname
            app_name -> appname
        """
        return re.sub(r"[^a-z0-9]", "", key.casefold())

    def resolve(
        self,
        extension_path: Path,
        value: str,
        default_locale: str = "",
    ) -> str:
        if not isinstance(value, str):
            return value

        match = self.MESSAGE_PATTERN.fullmatch(value)

        if not match:
            return value

        required_key = self._normalize_key(match.group(1))
        locales_path = extension_path / "_locales"

        if not locales_path.is_dir():
            return value

        locale_folders = [
            folder
            for folder in locales_path.iterdir()
            if folder.is_dir()
        ]

        # Check the manifest's default locale first, followed by English
        # variants and then every other available locale.
        preferred_names = [
            default_locale,
            "en_GB",
            "en",
            "en_US",
        ]

        ordered_folders: list[Path] = []

        for locale_name in preferred_names:
            if not locale_name:
                continue

            folder = locales_path / locale_name

            if folder.is_dir() and folder not in ordered_folders:
                ordered_folders.append(folder)

        for folder in sorted(
            locale_folders,
            key=lambda item: item.name.casefold(),
        ):
            if folder not in ordered_folders:
                ordered_folders.append(folder)

        for locale_folder in ordered_folders:
            messages_path = locale_folder / "messages.json"

            if not messages_path.is_file():
                continue

            try:
                with messages_path.open(
                    "r",
                    encoding="utf-8-sig",
                ) as file:
                    messages = json.load(file)

            except (OSError, UnicodeError, json.JSONDecodeError):
                continue

            for message_key, message_data in messages.items():
                normalized_message_key = self._normalize_key(
                    message_key
                )

                if normalized_message_key != required_key:
                    continue

                if not isinstance(message_data, dict):
                    continue

                resolved_message = message_data.get("message")

                if isinstance(resolved_message, str):
                    return resolved_message

        # Keep the original value if it cannot be resolved.
        return value