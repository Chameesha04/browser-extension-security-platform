from __future__ import annotations

from typing import Any

from analysis_engine.final_risk_engine import (
    FinalRiskEngine,
)

from analysis_engine.static_code_scorer import (
    StaticCodeScorer,
)

from analysis_engine.threat_intel_scorer import (
    ThreatIntelScorer,
)


ANALYZER_MODEL_VERSION = "extension-analyzer-v1"


class ExtensionAnalyzer:
    """
    Combine permission risk, threat intelligence,
    and static-code analysis into one final
    extension assessment.
    """

    def __init__(
        self,
        threat_intel_scorer: ThreatIntelScorer | None = None,
        static_code_scorer: StaticCodeScorer | None = None,
        final_risk_engine: FinalRiskEngine | None = None,
    ) -> None:

        self.threat_intel_scorer = (
            threat_intel_scorer
            or ThreatIntelScorer()
        )

        self.static_code_scorer = (
            static_code_scorer
            or StaticCodeScorer()
        )

        self.final_risk_engine = (
            final_risk_engine
            or FinalRiskEngine()
        )

    def analyze(
        self,
        *,
        permission_score: int,
        normalized_report: dict[str, Any],
        threat_intel_report: dict[str, Any],
    ) -> dict[str, Any]:

        # -----------------------------------
        # Threat intelligence scoring
        # -----------------------------------

        threat_intel_result = (
            self.threat_intel_scorer.score(
                threat_intel_report
            )
        )

        # -----------------------------------
        # Static code scoring
        # -----------------------------------

        static_code_result = (
            self.static_code_scorer.score(
                normalized_report
            )
        )

        # -----------------------------------
        # Final multi-factor score
        # -----------------------------------

        final_result = (
            self.final_risk_engine.calculate(
                permission_score=permission_score,
                threat_intel_score=(
                    threat_intel_result[
                        "score"
                    ]
                ),
                static_code_score=(
                    static_code_result[
                        "score"
                    ]
                ),
            )
        )

        extension_name = str(
            normalized_report.get(
                "extension_name",
                "Unknown",
            )
        )

        extension_id = str(
            normalized_report.get(
                "extension_id",
                "",
            )
        )

        extension_version = str(
            normalized_report.get(
                "extension_version",
                "",
            )
        )

        profile = str(
            normalized_report.get(
                "profile",
                "",
            )
        )

        cache_key = str(
            normalized_report.get(
                "cache_key",
                "",
            )
        )

        if not cache_key:
            cache_key = (
                f"{extension_id}:"
                f"{extension_version}"
            )

        return {
            "extension_name": (
                extension_name
            ),

            "extension_id": (
                extension_id
            ),

            "extension_version": (
                extension_version
            ),

            "profile": profile,

            "cache_key": cache_key,

            # Individual factors
            "permission_analysis": {
                "score": int(
                    permission_score
                )
            },

            "threat_intelligence_analysis": (
                threat_intel_result
            ),

            "static_code_analysis": (
                static_code_result
            ),

            # Final decision
            "final_assessment": (
                final_result
            ),

            "analyzer_model_version": (
                ANALYZER_MODEL_VERSION
            ),
        }