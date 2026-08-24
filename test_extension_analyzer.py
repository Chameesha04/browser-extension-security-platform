from analysis_engine.extension_analyzer import (
    ExtensionAnalyzer,
)


def main() -> None:

    analyzer = ExtensionAnalyzer()

    normalized_report = {
        "extension_name": "Demo Extension",
        "extension_id": "demo123",
        "extension_version": "1.0.0",
        "profile": "Default",
        "cache_key": "demo123:1.0.0",

        "code_analysis": {
            "high_confidence": [
                {
                    "indicator": "dynamic_eval",
                    "files_affected": 2,
                    "occurrences": 150,
                },
                {
                    "indicator": "function_constructor",
                    "files_affected": 1,
                    "occurrences": 40,
                },
            ],

            "medium_confidence": [
                {
                    "indicator": "base64_decode",
                    "files_affected": 2,
                    "occurrences": 100,
                },
            ],

            "low_confidence": [],
            "unknown_confidence": [],
        },
    }

    threat_intel_report = {
        "lookups": [
            {
                "indicator_type": "domain",
                "indicator": "example.com",
                "malicious": 0,
                "suspicious": 0,
            },

            {
                "indicator_type": "url",
                "indicator": "http://example.com/test",
                "malicious": 2,
                "suspicious": 0,
            },

            {
                "indicator_type": "file_hash",
                "indicator": "abc123",
                "malicious": 0,
                "suspicious": 0,
            },
        ]
    }

    result = analyzer.analyze(
        permission_score=40,
        normalized_report=(
            normalized_report
        ),
        threat_intel_report=(
            threat_intel_report
        ),
    )

    print(
        "\n===== Unified Extension Analysis ====="
    )

    print(
        f"Extension        : "
        f"{result['extension_name']}"
    )

    print(
        f"Permission Score : "
        f"{result['permission_analysis']['score']}"
    )

    print(
        f"Threat Intel     : "
        f"{result['threat_intelligence_analysis']['score']}"
    )

    print(
        f"Static Code      : "
        f"{result['static_code_analysis']['score']}"
    )

    final = result[
        "final_assessment"
    ]

    print(
        f"Final Score      : "
        f"{final['final_score']} / 100"
    )

    print(
        f"Final Severity   : "
        f"{final['final_severity']}"
    )

    print(
        f"Recommendation   : "
        f"{final['recommendation']}"
    )


if __name__ == "__main__":
    main()