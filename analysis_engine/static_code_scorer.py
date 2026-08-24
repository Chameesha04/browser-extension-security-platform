from __future__ import annotations

from typing import Any


STATIC_CODE_MODEL_VERSION = "static-code-v2"


class StaticCodeScorer:
    """
    Convert suspicious static JavaScript patterns into a
    bounded risk score.

    Important:
    - Raw occurrence counts do NOT directly determine risk.
    - Each technique is scored only once.
    - Confidence groups are capped.
    - Static analysis alone cannot produce Critical severity.
    """

    TECHNIQUE_WEIGHTS = {
        "dynamic_eval": 8,
        "function_constructor": 10,
        "repeated_hex_escapes": 6,
        "repeated_unicode_escapes": 6,
        "from_char_code": 4,
        "long_base64_blob": 4,
        "base64_decode": 2,
        "legacy_unescape": 2,
    }

    GROUP_CAPS = {
        "high_confidence": 30,
        "medium_confidence": 12,
        "low_confidence": 6,
        "unknown_confidence": 4,
    }

    def score(
        self,
        normalized_report: dict[str, Any],
    ) -> dict[str, Any]:

        code_analysis = normalized_report.get(
            "code_analysis",
            {},
        )

        if not isinstance(code_analysis, dict):
            code_analysis = {}

        technique_results: list[
            dict[str, Any]
        ] = []

        group_scores = {
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": 0,
            "unknown_confidence": 0,
        }

        detected_techniques: set[str] = set()

        for group_name in group_scores:

            findings = code_analysis.get(
                group_name,
                [],
            )

            if not isinstance(findings, list):
                continue

            for finding in findings:

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                indicator = str(
                    finding.get(
                        "indicator",
                        "",
                    )
                ).strip()

                if not indicator:
                    continue

                # Do not score the same technique multiple times.
                if indicator in detected_techniques:
                    continue

                detected_techniques.add(
                    indicator
                )

                try:
                    files_affected = int(
                        finding.get(
                            "files_affected",
                            0,
                        )
                    )

                except (
                    TypeError,
                    ValueError,
                ):
                    files_affected = 0

                try:
                    occurrences = int(
                        finding.get(
                            "occurrences",
                            0,
                        )
                    )

                except (
                    TypeError,
                    ValueError,
                ):
                    occurrences = 0

                base_weight = (
                    self.TECHNIQUE_WEIGHTS.get(
                        indicator,
                        2,
                    )
                )

                # File spread adds only limited risk.
                # Raw occurrence count is NOT multiplied.
                spread_bonus = min(
                    3,
                    max(
                        0,
                        files_affected - 1,
                    ),
                )

                contribution = (
                    base_weight
                    + spread_bonus
                )

                group_scores[
                    group_name
                ] += contribution

                technique_results.append(
                    {
                        "technique": (
                            indicator
                        ),
                        "confidence_group": (
                            group_name
                        ),
                        "files_affected": (
                            files_affected
                        ),
                        "raw_occurrences": (
                            occurrences
                        ),
                        "uncapped_contribution": (
                            contribution
                        ),
                    }
                )

        # Cap each confidence group's influence.
        for group_name, cap in (
            self.GROUP_CAPS.items()
        ):

            group_scores[
                group_name
            ] = min(
                group_scores[
                    group_name
                ],
                cap,
            )

        total_score = sum(
            group_scores.values()
        )

        # Combination bonus only when several
        # stronger techniques occur together.
        strong_techniques = {
            "dynamic_eval",
            "function_constructor",
            "repeated_hex_escapes",
            "repeated_unicode_escapes",
        }

        strong_detected = (
            detected_techniques
            & strong_techniques
        )

        combination_bonus = 0

        if len(strong_detected) >= 3:
            combination_bonus = 5

        total_score += combination_bonus

        # Static analysis alone must not
        # declare an extension Critical.
        total_score = min(
            60,
            total_score,
        )

        return {
            "score": total_score,

            "severity": self._severity(
                total_score
            ),

            "techniques_detected": len(
                detected_techniques
            ),

            "group_scores": (
                group_scores
            ),

            "combination_bonus": (
                combination_bonus
            ),

            "techniques": (
                technique_results
            ),

            "model_version": (
                STATIC_CODE_MODEL_VERSION
            ),
        }

    @staticmethod
    def _severity(
        score: int,
    ) -> str:

        if score >= 40:
            return "high"

        if score >= 20:
            return "medium"

        return "low"