from __future__ import annotations


FINAL_RISK_MODEL_VERSION = "final-risk-v1"


class FinalRiskEngine:

    PERMISSION_WEIGHT = 0.30
    THREAT_INTEL_WEIGHT = 0.45
    STATIC_CODE_WEIGHT = 0.25

    def calculate(
        self,
        permission_score: int,
        threat_intel_score: int,
        static_code_score: int,
    ) -> dict:

        permission_score = self._clamp(
            permission_score
        )

        threat_intel_score = self._clamp(
            threat_intel_score
        )

        static_code_score = self._clamp(
            static_code_score
        )

        weighted_score = (
            permission_score
            * self.PERMISSION_WEIGHT

            + threat_intel_score
            * self.THREAT_INTEL_WEIGHT

            + static_code_score
            * self.STATIC_CODE_WEIGHT
        )

        final_score = round(
            weighted_score
        )

        severity = self._severity(
            final_score
        )

        recommendation = (
            self._recommendation(
                final_score
            )
        )

        return {
            "final_score": final_score,
            "final_severity": severity,
            "recommendation": recommendation,

            "components": {
                "permission_score": (
                    permission_score
                ),
                "threat_intel_score": (
                    threat_intel_score
                ),
                "static_code_score": (
                    static_code_score
                ),
            },

            "weights": {
                "permission": (
                    self.PERMISSION_WEIGHT
                ),
                "threat_intelligence": (
                    self.THREAT_INTEL_WEIGHT
                ),
                "static_code": (
                    self.STATIC_CODE_WEIGHT
                ),
            },

            "model_version": (
                FINAL_RISK_MODEL_VERSION
            ),
        }

    @staticmethod
    def _clamp(
        value: int,
    ) -> int:

        return max(
            0,
            min(
                100,
                int(value),
            ),
        )

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
    def _recommendation(
        score: int,
    ) -> str:

        if score >= 70:
            return (
                "Investigate immediately "
                "and consider disabling"
            )

        if score >= 40:
            return (
                "Investigate extension "
                "and review evidence"
            )

        if score >= 20:
            return (
                "Monitor and review "
                "permissions"
            )

        return (
            "Low observed risk; "
            "continue monitoring"
        )