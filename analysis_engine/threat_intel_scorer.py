from __future__ import annotations

from typing import Any


THREAT_INTEL_MODEL_VERSION = "threat-intel-v1"


class ThreatIntelScorer:
    """
    Convert VirusTotal enrichment evidence into a bounded
    threat-intelligence score from 0 to 100.

    A small number of engine detections is treated as weak
    evidence rather than proof that an extension is malicious.
    """

    def score(
        self,
        threat_intel_report: dict[str, Any],
    ) -> dict[str, Any]:

        lookups = threat_intel_report.get(
            "lookups",
            [],
        )

        flagged_indicators = 0
        total_malicious = 0
        total_suspicious = 0
        maximum_malicious = 0

        evidence: list[dict[str, Any]] = []

        for lookup in lookups:

            if not isinstance(lookup, dict):
                continue

            malicious = int(
                lookup.get(
                    "malicious",
                    0,
                )
            )

            suspicious = int(
                lookup.get(
                    "suspicious",
                    0,
                )
            )

            total_malicious += malicious
            total_suspicious += suspicious

            maximum_malicious = max(
                maximum_malicious,
                malicious,
            )

            if malicious > 0 or suspicious > 0:
                flagged_indicators += 1

                evidence.append(
                    {
                        "type": lookup.get(
                            "indicator_type",
                            "",
                        ),
                        "indicator": lookup.get(
                            "indicator",
                            "",
                        ),
                        "malicious_engines": malicious,
                        "suspicious_engines": suspicious,
                    }
                )

        score = self._base_score(
            maximum_malicious
        )

        # Suspicious detections add limited weight.
        if total_suspicious > 0:
            score += min(
                10,
                total_suspicious * 2,
            )

        # Multiple independent indicators being flagged
        # increases confidence.
        if flagged_indicators >= 2:
            score += 10

        if flagged_indicators >= 3:
            score += 10

        score = min(
            100,
            score,
        )

        severity = self._severity(
            score
        )

        confidence = self._confidence(
            flagged_indicators=flagged_indicators,
            maximum_malicious=maximum_malicious,
        )

        return {
            "score": score,
            "severity": severity,
            "confidence": confidence,

            "indicators_checked": len(
                lookups
            ),

            "flagged_indicators": (
                flagged_indicators
            ),

            "total_malicious_engine_detections": (
                total_malicious
            ),

            "total_suspicious_engine_detections": (
                total_suspicious
            ),

            "maximum_malicious_engines_on_one_ioc": (
                maximum_malicious
            ),

            "evidence": evidence,

            "model_version": (
                THREAT_INTEL_MODEL_VERSION
            ),
        }

    @staticmethod
    def _base_score(
        malicious_engines: int,
    ) -> int:

        if malicious_engines <= 0:
            return 0

        if malicious_engines == 1:
            return 5

        if malicious_engines <= 3:
            return 15

        if malicious_engines <= 7:
            return 35

        if malicious_engines <= 14:
            return 60

        return 85

    @staticmethod
    def _severity(
        score: int,
    ) -> str:

        if score >= 70:
            return "critical"

        if score >= 40:
            return "high"

        if score >= 20:
            return "medium"

        return "low"

    @staticmethod
    def _confidence(
        flagged_indicators: int,
        maximum_malicious: int,
    ) -> str:

        if flagged_indicators == 0:
            return "none"

        if (
            flagged_indicators == 1
            and maximum_malicious <= 1
        ):
            return "low"

        if (
            flagged_indicators >= 2
            or maximum_malicious >= 4
        ):
            return "medium"

        if (
            flagged_indicators >= 3
            and maximum_malicious >= 8
        ):
            return "high"

        return "low"