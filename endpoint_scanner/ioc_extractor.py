from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class IOCExtractionError(RuntimeError):
    """Raised when indicators cannot be extracted from an extension."""


class IOCExtractor:
    """
    Extract locally observable indicators from a Chrome extension.

    This component performs static extraction only. It does not decide
    whether an indicator is malicious and does not contact any external
    threat-intelligence service.
    """

    TEXT_EXTENSIONS = {
        ".js",
        ".mjs",
        ".cjs",
        ".html",
        ".htm",
        ".json",
        ".css",
        ".txt",
    }

    HASH_EXTENSIONS = TEXT_EXTENSIONS | {
        ".wasm",
        ".dll",
        ".exe",
        ".dat",
        ".bin",
    }

    SKIPPED_DIRECTORIES = {
        ".git",
        "__pycache__",
        "node_modules",
    }

    URL_PATTERN = re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE,
    )

    IPV4_CANDIDATE_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    CHROME_MATCH_PATTERN = re.compile(
        r"(?:https?|\*)://(?:\*\.)?"
        r"(?P<domain>[A-Za-z0-9.-]+)",
        re.IGNORECASE,
    )

    SUSPICIOUS_PATTERNS = {
        "dynamic_eval": re.compile(
            r"\beval\s*\(",
            re.IGNORECASE,
        ),
        "function_constructor": re.compile(
            r"\bnew\s+Function\s*\(|"
            r"\bFunction\s*\(",
            re.IGNORECASE,
        ),
        "base64_decode": re.compile(
            r"\batob\s*\(",
            re.IGNORECASE,
        ),
        "legacy_unescape": re.compile(
            r"\bunescape\s*\(",
            re.IGNORECASE,
        ),
        "from_char_code": re.compile(
            r"\bString\.fromCharCode\s*\(",
            re.IGNORECASE,
        ),
        "long_base64_blob": re.compile(
            r"(?<![A-Za-z0-9+/])"
            r"[A-Za-z0-9+/]{200,}={0,2}"
            r"(?![A-Za-z0-9+/])"
        ),
        "repeated_hex_escapes": re.compile(
            r"(?:\\x[0-9A-Fa-f]{2}){8,}"
        ),
        "repeated_unicode_escapes": re.compile(
            r"(?:\\u[0-9A-Fa-f]{4}){6,}"
        ),
    }

    API_PATH_KEYWORDS = {
        "/api/",
        "/v1/",
        "/v2/",
        "/v3/",
        "graphql",
        "telemetry",
        "collect",
        "tracking",
        "upload",
        "events",
        "analytics",
    }

    def __init__(
        self,
        maximum_text_size: int = 5 * 1024 * 1024,
        maximum_hash_size: int = 25 * 1024 * 1024,
        maximum_findings_per_file: int = 50,
    ) -> None:
        self.maximum_text_size = maximum_text_size
        self.maximum_hash_size = maximum_hash_size
        self.maximum_findings_per_file = (
            maximum_findings_per_file
        )

    def extract(
        self,
        extension_path: Path,
        extension_id: str = "",
    ) -> dict[str, Any]:
        extension_path = Path(extension_path)

        if not extension_path.is_dir():
            raise IOCExtractionError(
                f"Extension directory does not exist: "
                f"{extension_path}"
            )

        manifest = self._load_manifest(
            extension_path / "manifest.json"
        )

        resolved_extension_id = (
            extension_id
            or self._infer_extension_id(extension_path)
        )

        urls: set[str] = set()
        domains: set[str] = set()
        ip_addresses: set[str] = set()
        api_endpoints: set[str] = set()
        chrome_match_domains: set[str] = set()

        file_hashes: list[dict[str, Any]] = []
        suspicious_indicators: list[dict[str, Any]] = []

        skipped_large_text_files: list[str] = []
        skipped_large_hash_files: list[str] = []

        files_scanned = 0
        text_files_scanned = 0

        for file_path in self._iter_extension_files(
            extension_path
        ):
            files_scanned += 1

            relative_path = file_path.relative_to(
                extension_path
            ).as_posix()

            suffix = file_path.suffix.lower()

            try:
                file_size = file_path.stat().st_size

            except OSError:
                continue

            if suffix in self.HASH_EXTENSIONS:
                if file_size <= self.maximum_hash_size:
                    file_hashes.append(
                        {
                            "file": relative_path,
                            "sha256": self._calculate_sha256(
                                file_path
                            ),
                            "size_bytes": file_size,
                            "file_type": (
                                suffix.lstrip(".")
                                or "unknown"
                            ),
                        }
                    )
                else:
                    skipped_large_hash_files.append(
                        relative_path
                    )

            if suffix not in self.TEXT_EXTENSIONS:
                continue

            if file_size > self.maximum_text_size:
                skipped_large_text_files.append(
                    relative_path
                )
                continue

            text = self._read_text(file_path)

            if text is None:
                continue

            text_files_scanned += 1

            file_urls = self._extract_urls(text)

            for url in file_urls:
                urls.add(url)

                domain = self._domain_from_url(url)

                if domain:
                    domains.add(domain)

                if self._looks_like_api_endpoint(url):
                    api_endpoints.add(url)

            for ip_address in self._extract_ip_addresses(
                text
            ):
                ip_addresses.add(ip_address)

            for domain in self._extract_match_domains(text):
                chrome_match_domains.add(domain)
                domains.add(domain)

            suspicious_indicators.extend(
                self._extract_suspicious_patterns(
                    text=text,
                    relative_path=relative_path,
                )
            )

        update_url = self._safe_string(
            manifest.get("update_url")
        )

        homepage_url = self._safe_string(
            manifest.get("homepage_url")
        )

        for manifest_url in (
            update_url,
            homepage_url,
        ):
            if not manifest_url:
                continue

            urls.add(manifest_url)

            domain = self._domain_from_url(
                manifest_url
            )

            if domain:
                domains.add(domain)

            if self._looks_like_api_endpoint(
                manifest_url
            ):
                api_endpoints.add(manifest_url)

        manifest_match_patterns = (
            self._extract_manifest_match_patterns(
                manifest
            )
        )

        for match_pattern in manifest_match_patterns:
            for domain in self._extract_match_domains(
                match_pattern
            ):
                chrome_match_domains.add(domain)
                domains.add(domain)

        web_accessible_resources = (
            self._extract_web_accessible_resources(
                manifest
            )
        )

        return {
            "extension_id": resolved_extension_id,
            "extension_version": extension_path.name,
            "extension_path": str(
                extension_path.resolve()
            ),
            "update_url": update_url,
            "homepage_url": homepage_url,
            "urls": sorted(urls),
            "domains": sorted(domains),
            "ip_addresses": sorted(ip_addresses),
            "api_endpoints": sorted(api_endpoints),
            "chrome_match_patterns": sorted(
                manifest_match_patterns
            ),
            "chrome_match_domains": sorted(
                chrome_match_domains
            ),
            "web_accessible_resources": (
                web_accessible_resources
            ),
            "file_hashes": file_hashes,
            "suspicious_indicators": (
                suspicious_indicators
            ),
            "summary": {
                "files_scanned": files_scanned,
                "text_files_scanned": (
                    text_files_scanned
                ),
                "hashes_calculated": len(
                    file_hashes
                ),
                "url_count": len(urls),
                "domain_count": len(domains),
                "ip_address_count": len(
                    ip_addresses
                ),
                "api_endpoint_count": len(
                    api_endpoints
                ),
                "suspicious_indicator_count": len(
                    suspicious_indicators
                ),
            },
            "skipped_files": {
                "large_text_files": (
                    skipped_large_text_files
                ),
                "large_hash_files": (
                    skipped_large_hash_files
                ),
            },
        }

    def _iter_extension_files(
        self,
        extension_path: Path,
    ):
        for file_path in extension_path.rglob("*"):
            if not file_path.is_file():
                continue

            relative_parts = file_path.relative_to(
                extension_path
            ).parts

            if any(
                part in self.SKIPPED_DIRECTORIES
                for part in relative_parts
            ):
                continue

            yield file_path

    @staticmethod
    def _load_manifest(
        manifest_path: Path,
    ) -> dict[str, Any]:
        if not manifest_path.is_file():
            return {}

        try:
            with manifest_path.open(
                "r",
                encoding="utf-8-sig",
            ) as manifest_file:
                manifest = json.load(
                    manifest_file
                )

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            return {}

        return (
            manifest
            if isinstance(manifest, dict)
            else {}
        )

    @staticmethod
    def _read_text(
        file_path: Path,
    ) -> str | None:
        try:
            return file_path.read_text(
                encoding="utf-8-sig",
                errors="ignore",
            )

        except OSError:
            return None

    @staticmethod
    def _calculate_sha256(
        file_path: Path,
    ) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as input_file:
            for chunk in iter(
                lambda: input_file.read(
                    1024 * 1024
                ),
                b"",
            ):
                digest.update(chunk)

        return digest.hexdigest()

    def _extract_urls(
        self,
        text: str,
    ) -> set[str]:
        """
        Extract valid HTTP and HTTPS URLs.

        Extension source code may contain templates, regular expressions,
        placeholders or incomplete URLs. Invalid values are ignored instead
        of stopping the complete IOC scan.
        """

        urls: set[str] = set()

        for match in self.URL_PATTERN.findall(text):
            cleaned_url = match.rstrip(
                ".,;:)]}>\\"
            )

            if not cleaned_url:
                continue

            try:
                parsed = urlparse(cleaned_url)

            except ValueError:
                continue

            if parsed.scheme.lower() not in {
                "http",
                "https",
            }:
                continue

            if not parsed.netloc:
                continue

            urls.add(cleaned_url)

        return urls

    def _extract_ip_addresses(
        self,
        text: str,
    ) -> set[str]:
        addresses: set[str] = set()

        for candidate in (
            self.IPV4_CANDIDATE_PATTERN.findall(
                text
            )
        ):
            try:
                address = ipaddress.ip_address(
                    candidate
                )

            except ValueError:
                continue

            if isinstance(
                address,
                ipaddress.IPv4Address,
            ):
                addresses.add(str(address))

        return addresses

    def _extract_match_domains(
        self,
        text: str,
    ) -> set[str]:
        domains: set[str] = set()

        for match in (
            self.CHROME_MATCH_PATTERN.finditer(
                text
            )
        ):
            domain = match.group(
                "domain"
            ).lower()

            if domain and domain != "*":
                domains.add(domain)

        return domains

    def _extract_suspicious_patterns(
        self,
        text: str,
        relative_path: str,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for line_number, line in enumerate(
            text.splitlines(),
            start=1,
        ):
            for indicator_name, pattern in (
                self.SUSPICIOUS_PATTERNS.items()
            ):
                matches = list(
                    pattern.finditer(line)
                )

                if not matches:
                    continue

                findings.append(
                    {
                        "file": relative_path,
                        "line": line_number,
                        "indicator": (
                            indicator_name
                        ),
                        "count": len(matches),
                        "evidence": self._shorten(
                            line.strip(),
                            maximum_length=180,
                        ),
                    }
                )

                if (
                    len(findings)
                    >= self.maximum_findings_per_file
                ):
                    return findings

        return findings

    def _extract_manifest_match_patterns(
        self,
        manifest: dict[str, Any],
    ) -> set[str]:
        patterns: set[str] = set()

        for field_name in (
            "permissions",
            "host_permissions",
            "optional_permissions",
            "optional_host_permissions",
        ):
            values = manifest.get(
                field_name,
                []
            )

            if not isinstance(values, list):
                continue

            for value in values:
                if not isinstance(value, str):
                    continue

                if "://" in value:
                    patterns.add(value)

        content_scripts = manifest.get(
            "content_scripts",
            []
        )

        if isinstance(content_scripts, list):
            for content_script in content_scripts:
                if not isinstance(
                    content_script,
                    dict,
                ):
                    continue

                matches = content_script.get(
                    "matches",
                    []
                )

                if isinstance(matches, list):
                    patterns.update(
                        value
                        for value in matches
                        if isinstance(
                            value,
                            str,
                        )
                    )

        external_connectable = manifest.get(
            "externally_connectable",
            {}
        )

        if isinstance(
            external_connectable,
            dict,
        ):
            matches = external_connectable.get(
                "matches",
                []
            )

            if isinstance(matches, list):
                patterns.update(
                    value
                    for value in matches
                    if isinstance(
                        value,
                        str,
                    )
                )

        return patterns

    @staticmethod
    def _extract_web_accessible_resources(
        manifest: dict[str, Any],
    ) -> list[str]:
        resources = manifest.get(
            "web_accessible_resources",
            []
        )

        extracted: set[str] = set()

        if not isinstance(resources, list):
            return []

        for resource in resources:
            if isinstance(resource, str):
                extracted.add(resource)

            elif isinstance(resource, dict):
                entries = resource.get(
                    "resources",
                    []
                )

                if isinstance(entries, list):
                    extracted.update(
                        entry
                        for entry in entries
                        if isinstance(
                            entry,
                            str,
                        )
                    )

        return sorted(extracted)

    def _looks_like_api_endpoint(
        self,
        url: str,
    ) -> bool:
        try:
            parsed = urlparse(url)

        except ValueError:
            return False

        searchable_value = (
            f"{parsed.netloc}{parsed.path}"
        ).lower()

        return any(
            keyword in searchable_value
            for keyword in self.API_PATH_KEYWORDS
        )

    @staticmethod
    def _domain_from_url(
        url: str,
    ) -> str:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname

        except ValueError:
            return ""

        return (
            hostname.lower()
            if hostname
            else ""
        )

    @staticmethod
    def _infer_extension_id(
        extension_path: Path,
    ) -> str:
        parent_name = (
            extension_path.parent.name
        )

        if (
            len(parent_name) == 32
            and all(
                "a" <= character <= "p"
                for character in parent_name
            )
        ):
            return parent_name

        return ""

    @staticmethod
    def _safe_string(
        value: Any,
    ) -> str:
        return (
            value
            if isinstance(value, str)
            else ""
        )

    @staticmethod
    def _shorten(
        value: str,
        maximum_length: int,
    ) -> str:
        if len(value) <= maximum_length:
            return value

        return (
            value[: maximum_length - 3]
            + "..."
        )