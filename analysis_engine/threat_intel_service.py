from __future__ import annotations

from typing import Any

from analysis_engine.virustotal_client import (
    VirusTotalClient,
    VirusTotalError,
)


class ThreatIntelService:
    """
    Enrich normalized Chrome extension IOCs using
    external threat-intelligence providers.

    Current provider:
        - VirusTotal

    This service only performs existing-report lookups.
    It does not upload extension files or submit URLs.
    """

    def __init__(
        self,
        virustotal_client: VirusTotalClient | None = None,
        maximum_domains: int = 1,
        maximum_urls: int = 1,
        maximum_hashes: int = 1,
        maximum_ips: int = 0,
    ) -> None:

        self.virustotal = (
            virustotal_client
            or VirusTotalClient()
        )

        self.maximum_domains = maximum_domains
        self.maximum_urls = maximum_urls
        self.maximum_hashes = maximum_hashes
        self.maximum_ips = maximum_ips

    def enrich(
        self,
        normalized_report: dict[str, Any],
    ) -> dict[str, Any]:

        candidates = normalized_report.get(
            "threat_intel_candidates",
            {},
        )

        results: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []

        # -----------------------------
        # Domains
        # -----------------------------

        domains = candidates.get(
            "domains",
            [],
        )

        for domain in domains[
            : self.maximum_domains
        ]:
            self._perform_lookup(
                lookup_type="domain",
                indicator=domain,
                lookup_function=(
                    self.virustotal.lookup_domain
                ),
                results=results,
                errors=errors,
            )

        # -----------------------------
        # URLs
        # -----------------------------

        urls = candidates.get(
            "urls",
            [],
        )

        for url in urls[
            : self.maximum_urls
        ]:
            self._perform_lookup(
                lookup_type="url",
                indicator=url,
                lookup_function=(
                    self.virustotal.lookup_url
                ),
                results=results,
                errors=errors,
            )

        # -----------------------------
        # File hashes
        # -----------------------------

        hashes = candidates.get(
            "file_hashes",
            [],
        )

        for hash_entry in hashes[
            : self.maximum_hashes
        ]:

            if isinstance(
                hash_entry,
                dict,
            ):
                sha256 = str(
                    hash_entry.get(
                        "sha256",
                        "",
                    )
                )

            else:
                sha256 = str(
                    hash_entry
                )

            if not sha256:
                continue

            self._perform_lookup(
                lookup_type="file_hash",
                indicator=sha256,
                lookup_function=(
                    self.virustotal.lookup_file_hash
                ),
                results=results,
                errors=errors,
            )

        # -----------------------------
        # IP addresses
        # -----------------------------

        ip_addresses = candidates.get(
            "ip_addresses",
            [],
        )

        for ip_address in ip_addresses[
            : self.maximum_ips
        ]:
            self._perform_lookup(
                lookup_type="ip",
                indicator=ip_address,
                lookup_function=(
                    self.virustotal.lookup_ip
                ),
                results=results,
                errors=errors,
            )

        summary = self._build_summary(
            results=results,
            errors=errors,
        )

        return {
            "extension_id": normalized_report.get(
                "extension_id",
                "",
            ),

            "extension_name": normalized_report.get(
                "extension_name",
                "",
            ),

            "extension_version": normalized_report.get(
                "extension_version",
                "",
            ),

            "cache_key": normalized_report.get(
                "cache_key",
                "",
            ),

            "provider": "VirusTotal",

            "lookups": results,

            "errors": errors,

            "summary": summary,
        }

    def _perform_lookup(
        self,
        lookup_type: str,
        indicator: str,
        lookup_function,
        results: list[dict[str, Any]],
        errors: list[dict[str, str]],
    ) -> None:

        print(
            f"Checking {lookup_type}: "
            f"{self._shorten(indicator)}"
        )

        try:
            result = lookup_function(
                indicator
            )

        except VirusTotalError as error:
            errors.append(
                {
                    "type": lookup_type,
                    "indicator": indicator,
                    "error": str(error),
                }
            )

            print(
                f"  VirusTotal error: "
                f"{error}"
            )

            return

        results.append(
            result
        )

        print(
            f"  Malicious : "
            f"{result.get('malicious', 0)}"
        )

        print(
            f"  Suspicious: "
            f"{result.get('suspicious', 0)}"
        )

        print(
            f"  Source    : "
            f"{result.get('source', 'unknown')}"
        )

    @staticmethod
    def _build_summary(
        results: list[dict[str, Any]],
        errors: list[dict[str, str]],
    ) -> dict[str, int]:

        found_count = 0
        not_found_count = 0

        malicious_indicator_count = 0
        suspicious_indicator_count = 0

        total_malicious_detections = 0
        total_suspicious_detections = 0

        for result in results:

            status = result.get(
                "status",
                "",
            )

            if status == "found":
                found_count += 1

            elif status == "not_found":
                not_found_count += 1

            malicious = int(
                result.get(
                    "malicious",
                    0,
                )
            )

            suspicious = int(
                result.get(
                    "suspicious",
                    0,
                )
            )

            total_malicious_detections += (
                malicious
            )

            total_suspicious_detections += (
                suspicious
            )

            if malicious > 0:
                malicious_indicator_count += 1

            if suspicious > 0:
                suspicious_indicator_count += 1

        return {
            "indicators_checked": len(
                results
            ),

            "reports_found": found_count,

            "reports_not_found": (
                not_found_count
            ),

            "indicators_with_malicious_detections": (
                malicious_indicator_count
            ),

            "indicators_with_suspicious_detections": (
                suspicious_indicator_count
            ),

            "total_malicious_engine_detections": (
                total_malicious_detections
            ),

            "total_suspicious_engine_detections": (
                total_suspicious_detections
            ),

            "lookup_errors": len(
                errors
            ),
        }

    @staticmethod
    def _shorten(
        value: str,
        maximum_length: int = 90,
    ) -> str:

        if len(value) <= maximum_length:
            return value

        return (
            value[
                : maximum_length - 3
            ]
            + "..."
        )