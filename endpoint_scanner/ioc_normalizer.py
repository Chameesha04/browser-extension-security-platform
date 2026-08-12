from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse, urlunparse


class IOCNormalizer:
    """
    Clean and prioritize raw indicators extracted from Chrome extensions.

    This class does NOT contact threat-intelligence services and does
    NOT decide whether an extension is malicious.
    """

    HIGH_CONFIDENCE_SIGNALS = {
        "dynamic_eval",
        "function_constructor",
        "repeated_hex_escapes",
        "repeated_unicode_escapes",
    }

    MEDIUM_CONFIDENCE_SIGNALS = {
        "from_char_code",
        "long_base64_blob",
    }

    LOW_CONFIDENCE_SIGNALS = {
        "base64_decode",
        "legacy_unescape",
    }

    DOMAIN_PATTERN = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:"
        r"[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"\."
        r")+"
        r"[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"$",
        re.IGNORECASE,
    )

    TEMPLATE_MARKERS = {
        "${",
        "{{",
        "}}",
        "<%",
        "%>",
        "[[",
        "]]",
    }

    EXECUTABLE_FILE_TYPES = {
        "exe",
        "dll",
        "wasm",
    }

    def __init__(
        self,
        maximum_hash_candidates: int = 50,
    ) -> None:
        self.maximum_hash_candidates = (
            maximum_hash_candidates
        )

    def normalize_report(
        self,
        report: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Normalize one raw IOC report.
        """

        normalized_urls = self._normalize_urls(
            report.get("urls", [])
        )

        normalized_domains = self._normalize_domains(
            report.get("domains", [])
        )

        normalized_ips = self._classify_ip_addresses(
            report.get("ip_addresses", [])
        )

        suspicious_summary = (
            self._summarize_suspicious_indicators(
                report.get(
                    "suspicious_indicators",
                    [],
                )
            )
        )

        hash_candidates = (
            self._select_hash_candidates(
                file_hashes=report.get(
                    "file_hashes",
                    [],
                ),
                suspicious_indicators=report.get(
                    "suspicious_indicators",
                    [],
                ),
            )
        )

        extension_id = str(
            report.get("extension_id", "")
        )

        extension_version = str(
            report.get("extension_version", "")
        )

        threat_intel_candidates = {
            "extension_id": extension_id,
            "urls": normalized_urls["candidates"],
            "domains": normalized_domains["candidates"],
            "ip_addresses": normalized_ips[
                "public"
            ],
            "file_hashes": hash_candidates,
        }

        return {
            "extension_id": extension_id,
            "extension_name": report.get(
                "extension_name",
                "",
            ),
            "extension_version": extension_version,
            "profile": report.get(
                "profile",
                "",
            ),

            # Useful later for caching threat-intelligence results.
            "cache_key": (
                f"{extension_id}:{extension_version}"
            ),

            "normalized_urls": normalized_urls,
            "normalized_domains": normalized_domains,
            "normalized_ip_addresses": normalized_ips,

            "code_analysis": suspicious_summary,

            "threat_intel_candidates": (
                threat_intel_candidates
            ),

            "summary": {
                "url_candidates": len(
                    normalized_urls["candidates"]
                ),
                "domain_candidates": len(
                    normalized_domains["candidates"]
                ),
                "public_ip_candidates": len(
                    normalized_ips["public"]
                ),
                "hash_candidates": len(
                    hash_candidates
                ),
                "high_confidence_code_signals": (
                    suspicious_summary[
                        "high_confidence_count"
                    ]
                ),
                "medium_confidence_code_signals": (
                    suspicious_summary[
                        "medium_confidence_count"
                    ]
                ),
                "low_confidence_code_signals": (
                    suspicious_summary[
                        "low_confidence_count"
                    ]
                ),
            },
        }

    def _normalize_urls(
        self,
        urls: list[str],
    ) -> dict[str, Any]:
        candidates: set[str] = set()
        excluded: list[dict[str, str]] = []

        for raw_url in urls:
            if not isinstance(raw_url, str):
                continue

            url = raw_url.strip()

            if not url:
                continue

            if self._contains_template_marker(url):
                excluded.append(
                    {
                        "value": url,
                        "reason": "template_or_placeholder",
                    }
                )
                continue

            try:
                parsed = urlparse(url)

                hostname = parsed.hostname

            except ValueError:
                excluded.append(
                    {
                        "value": url,
                        "reason": "invalid_url",
                    }
                )
                continue

            if parsed.scheme.lower() not in {
                "http",
                "https",
            }:
                excluded.append(
                    {
                        "value": url,
                        "reason": "unsupported_scheme",
                    }
                )
                continue

            if not hostname:
                excluded.append(
                    {
                        "value": url,
                        "reason": "missing_hostname",
                    }
                )
                continue

            hostname = hostname.lower()

            if (
                hostname == "localhost"
                or hostname.endswith(".localhost")
                or hostname.endswith(".local")
            ):
                excluded.append(
                    {
                        "value": url,
                        "reason": "local_hostname",
                    }
                )
                continue

            try:
                address = ipaddress.ip_address(
                    hostname
                )

            except ValueError:
                address = None

            if (
                address is not None
                and not address.is_global
            ):
                excluded.append(
                    {
                        "value": url,
                        "reason": (
                            "non_public_ip_destination"
                        ),
                    }
                )
                continue

            normalized = urlunparse(
                (
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    "",  # Remove fragment.
                )
            )

            candidates.add(normalized)

        return {
            "candidates": sorted(candidates),
            "excluded": excluded,
        }

    def _normalize_domains(
        self,
        domains: list[str],
    ) -> dict[str, Any]:
        candidates: set[str] = set()
        excluded: list[dict[str, str]] = []

        for raw_domain in domains:
            if not isinstance(
                raw_domain,
                str,
            ):
                continue

            domain = (
                raw_domain
                .strip()
                .lower()
                .rstrip(".")
            )

            domain = domain.removeprefix("*.")

            if not domain:
                continue

            if (
                domain == "localhost"
                or domain.endswith(".local")
                or domain.endswith(".localhost")
            ):
                excluded.append(
                    {
                        "value": domain,
                        "reason": "local_domain",
                    }
                )
                continue

            try:
                address = ipaddress.ip_address(
                    domain
                )

            except ValueError:
                address = None

            if address is not None:
                excluded.append(
                    {
                        "value": domain,
                        "reason": (
                            "ip_address_not_domain"
                        ),
                    }
                )
                continue

            if not self.DOMAIN_PATTERN.fullmatch(
                domain
            ):
                excluded.append(
                    {
                        "value": domain,
                        "reason": "invalid_domain",
                    }
                )
                continue

            candidates.add(domain)

        return {
            "candidates": sorted(candidates),
            "excluded": excluded,
        }

    def _classify_ip_addresses(
        self,
        ip_addresses: list[str],
    ) -> dict[str, list[str]]:
        public: set[str] = set()
        private: set[str] = set()
        reserved: set[str] = set()
        invalid: set[str] = set()

        for value in ip_addresses:
            if not isinstance(value, str):
                continue

            try:
                address = ipaddress.ip_address(
                    value.strip()
                )

            except ValueError:
                invalid.add(value)
                continue

            normalized = str(address)

            if address.is_global:
                public.add(normalized)

            elif (
                address.is_private
                or address.is_loopback
                or address.is_link_local
            ):
                private.add(normalized)

            else:
                reserved.add(normalized)

        return {
            "public": sorted(public),
            "private": sorted(private),
            "reserved": sorted(reserved),
            "invalid": sorted(invalid),
        }

    def _summarize_suspicious_indicators(
        self,
        indicators: list[dict[str, Any]],
    ) -> dict[str, Any]:
        occurrence_counts: Counter[str] = Counter()

        files_by_indicator: dict[
            str,
            set[str],
        ] = defaultdict(set)

        for finding in indicators:
            if not isinstance(
                finding,
                dict,
            ):
                continue

            indicator = str(
                finding.get(
                    "indicator",
                    "unknown",
                )
            )

            try:
                count = int(
                    finding.get(
                        "count",
                        1,
                    )
                )

            except (
                TypeError,
                ValueError,
            ):
                count = 1

            occurrence_counts[indicator] += max(
                count,
                1,
            )

            file_name = finding.get(
                "file",
                "",
            )

            if file_name:
                files_by_indicator[
                    indicator
                ].add(
                    str(file_name)
                )

        grouped = {
            "high": [],
            "medium": [],
            "low": [],
            "unknown": [],
        }

        for indicator, count in (
            occurrence_counts.items()
        ):
            confidence = self._confidence_for(
                indicator
            )

            grouped[confidence].append(
                {
                    "indicator": indicator,
                    "occurrences": count,
                    "files_affected": len(
                        files_by_indicator[
                            indicator
                        ]
                    ),
                }
            )

        for group in grouped.values():
            group.sort(
                key=lambda item: (
                    -item["occurrences"],
                    item["indicator"],
                )
            )

        return {
            "high_confidence": grouped["high"],
            "medium_confidence": grouped["medium"],
            "low_confidence": grouped["low"],
            "unknown_confidence": grouped["unknown"],

            "high_confidence_count": sum(
                item["occurrences"]
                for item in grouped["high"]
            ),

            "medium_confidence_count": sum(
                item["occurrences"]
                for item in grouped["medium"]
            ),

            "low_confidence_count": sum(
                item["occurrences"]
                for item in grouped["low"]
            ),
        }

    def _select_hash_candidates(
        self,
        file_hashes: list[dict[str, Any]],
        suspicious_indicators: list[
            dict[str, Any]
        ],
    ) -> list[dict[str, Any]]:
        suspicious_files = {
            str(finding.get("file"))
            for finding in suspicious_indicators
            if isinstance(finding, dict)
            and finding.get("file")
        }

        candidates: list[dict[str, Any]] = []

        seen_hashes: set[str] = set()

        for file_hash in file_hashes:
            if not isinstance(
                file_hash,
                dict,
            ):
                continue

            sha256 = str(
                file_hash.get(
                    "sha256",
                    "",
                )
            ).lower()

            file_name = str(
                file_hash.get(
                    "file",
                    "",
                )
            )

            file_type = str(
                file_hash.get(
                    "file_type",
                    "",
                )
            ).lower()

            if not sha256:
                continue

            if sha256 in seen_hashes:
                continue

            interesting_file = (
                file_name in suspicious_files
                or file_type
                in self.EXECUTABLE_FILE_TYPES
            )

            if not interesting_file:
                continue

            seen_hashes.add(sha256)

            candidates.append(
                {
                    "file": file_name,
                    "sha256": sha256,
                    "file_type": file_type,
                    "size_bytes": file_hash.get(
                        "size_bytes",
                        0,
                    ),
                }
            )

            if (
                len(candidates)
                >= self.maximum_hash_candidates
            ):
                break

        return candidates

    def _confidence_for(
        self,
        indicator: str,
    ) -> str:
        if (
            indicator
            in self.HIGH_CONFIDENCE_SIGNALS
        ):
            return "high"

        if (
            indicator
            in self.MEDIUM_CONFIDENCE_SIGNALS
        ):
            return "medium"

        if (
            indicator
            in self.LOW_CONFIDENCE_SIGNALS
        ):
            return "low"

        return "unknown"

    def _contains_template_marker(
        self,
        value: str,
    ) -> bool:
        return any(
            marker in value
            for marker in self.TEMPLATE_MARKERS
        )