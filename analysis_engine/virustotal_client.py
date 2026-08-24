from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from typing import Any

import requests


class VirusTotalError(RuntimeError):
    """Raised when a VirusTotal request cannot be completed."""


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str | None = None,
        cache_path: Path | None = None,
        request_interval: float = 16.0,
        timeout: float = 20.0,
    ) -> None:

        self.api_key = (
            api_key
            or os.getenv("VT_API_KEY", "")
        ).strip()

        if not self.api_key:
            raise VirusTotalError(
                "VT_API_KEY is not configured."
            )

        self.cache_path = cache_path or Path(
            "logs/threat_intel_cache/virustotal.json"
        )

        self.request_interval = request_interval
        self.timeout = timeout

        self.last_request_time = 0.0

        self.cache = self._load_cache()

    def lookup_domain(
        self,
        domain: str,
    ) -> dict[str, Any]:

        domain = domain.strip().lower()

        return self._lookup(
            indicator_type="domain",
            indicator=domain,
            endpoint=f"/domains/{domain}",
        )

    def lookup_file_hash(
        self,
        sha256: str,
    ) -> dict[str, Any]:

        sha256 = sha256.strip().lower()

        return self._lookup(
            indicator_type="file_hash",
            indicator=sha256,
            endpoint=f"/files/{sha256}",
        )

    def lookup_ip(
        self,
        ip_address: str,
    ) -> dict[str, Any]:

        ip_address = ip_address.strip()

        return self._lookup(
            indicator_type="ip",
            indicator=ip_address,
            endpoint=f"/ip_addresses/{ip_address}",
        )

    def lookup_url(
        self,
        url: str,
    ) -> dict[str, Any]:

        url = url.strip()

        encoded_url = (
            base64.urlsafe_b64encode(
                url.encode("utf-8")
            )
            .decode("ascii")
            .rstrip("=")
        )

        return self._lookup(
            indicator_type="url",
            indicator=url,
            endpoint=f"/urls/{encoded_url}",
        )

    def _lookup(
        self,
        indicator_type: str,
        indicator: str,
        endpoint: str,
    ) -> dict[str, Any]:

        cache_key = (
            f"{indicator_type}:{indicator}"
        )

        cached_result = self.cache.get(
            cache_key
        )

        if cached_result:
            return {
                **cached_result,
                "source": "cache",
            }

        self._wait_if_needed()

        try:
            response = requests.get(
                self.BASE_URL + endpoint,
                headers={
                    "x-apikey": self.api_key,
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )

        except requests.RequestException as error:
            raise VirusTotalError(
                f"VirusTotal connection failed: {error}"
            ) from error

        self.last_request_time = time.monotonic()

        if response.status_code == 404:
            result = {
                "indicator_type": indicator_type,
                "indicator": indicator,
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "source": "virustotal",
            }

            self._save_to_cache(
                cache_key,
                result,
            )

            return result

        if response.status_code == 429:
            raise VirusTotalError(
                "VirusTotal API rate limit reached."
            )

        if response.status_code in {
            401,
            403,
        }:
            raise VirusTotalError(
                "VirusTotal API key was rejected."
            )

        try:
            response.raise_for_status()

        except requests.RequestException as error:
            raise VirusTotalError(
                f"VirusTotal returned an error: {error}"
            ) from error

        payload = response.json()

        attributes = (
            payload
            .get("data", {})
            .get("attributes", {})
        )

        statistics = attributes.get(
            "last_analysis_stats",
            {},
        )

        result = {
            "indicator_type": indicator_type,
            "indicator": indicator,
            "status": "found",

            "malicious": int(
                statistics.get(
                    "malicious",
                    0,
                )
            ),

            "suspicious": int(
                statistics.get(
                    "suspicious",
                    0,
                )
            ),

            "harmless": int(
                statistics.get(
                    "harmless",
                    0,
                )
            ),

            "undetected": int(
                statistics.get(
                    "undetected",
                    0,
                )
            ),

            "reputation": attributes.get(
                "reputation"
            ),

            "last_analysis_date": (
                attributes.get(
                    "last_analysis_date"
                )
            ),

            "source": "virustotal",
        }

        self._save_to_cache(
            cache_key,
            result,
        )

        return result

    def _wait_if_needed(self) -> None:

        if self.last_request_time == 0:
            return

        elapsed = (
            time.monotonic()
            - self.last_request_time
        )

        remaining = (
            self.request_interval
            - elapsed
        )

        if remaining > 0:
            print(
                f"Waiting {remaining:.1f}s "
                f"for VirusTotal API quota..."
            )

            time.sleep(remaining)

    def _load_cache(
        self,
    ) -> dict[str, Any]:

        if not self.cache_path.is_file():
            return {}

        try:
            with self.cache_path.open(
                "r",
                encoding="utf-8",
            ) as cache_file:

                content = json.load(
                    cache_file
                )

        except (
            OSError,
            json.JSONDecodeError,
        ):
            return {}

        if isinstance(content, dict):
            return content

        return {}

    def _save_to_cache(
        self,
        cache_key: str,
        result: dict[str, Any],
    ) -> None:

        self.cache[
            cache_key
        ] = result

        self.cache_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = (
            self.cache_path.with_suffix(
                ".json.tmp"
            )
        )

        with temporary_path.open(
            "w",
            encoding="utf-8",
        ) as cache_file:

            json.dump(
                self.cache,
                cache_file,
                indent=4,
                ensure_ascii=False,
            )

        temporary_path.replace(
            self.cache_path
        )