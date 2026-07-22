from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Extension:
    # Browser and profile
    browser: str
    profile: str

    # Extension identity
    extension_id: str
    version: str
    path: Path

    # Manifest metadata
    name: str = ""
    description: str = ""
    default_locale: str = ""
    manifest_version: int = 0

    permissions: list[str] = field(default_factory=list)
    host_permissions: list[str] = field(default_factory=list)
    optional_permissions: list[str] = field(default_factory=list)

    background: dict[str, Any] = field(default_factory=dict)
    content_scripts: list[dict[str, Any]] = field(default_factory=list)
    action: dict[str, Any] = field(default_factory=dict)
    icons: dict[str, str] = field(default_factory=dict)

    homepage_url: str = ""
    update_url: str = ""

    # File collection—implemented later
    javascript_files: list[str] = field(default_factory=list)
    html_files: list[str] = field(default_factory=list)
    css_files: list[str] = field(default_factory=list)
    file_hashes: dict[str, str] = field(default_factory=dict)

    # Analysis—implemented later
    findings: list[dict[str, Any]] = field(default_factory=list)
    risk_score: int | None = None
    severity: str = "unscored"
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert the extension to a JSON-compatible dictionary."""
        result = asdict(self)
        result["path"] = str(self.path)
        return result