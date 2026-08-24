from analysis_engine.final_risk_engine import FinalRiskEngine


def main() -> None:
    engine = FinalRiskEngine()

    test_cases = [
        {
            "name": "Low-risk example",
            "permission": 10,
            "threat_intel": 0,
            "static_code": 8,
        },
        {
            "name": "Permission-heavy legitimate example",
            "permission": 100,
            "threat_intel": 0,
            "static_code": 10,
        },
        {
            "name": "Moderate threat evidence",
            "permission": 30,
            "threat_intel": 35,
            "static_code": 25,
        },
        {
            "name": "Strong malicious evidence",
            "permission": 80,
            "threat_intel": 85,
            "static_code": 60,
        },
    ]

    print("\n===== Final Risk Engine Test =====")

    for case in test_cases:
        result = engine.calculate(
            permission_score=case["permission"],
            threat_intel_score=case["threat_intel"],
            static_code_score=case["static_code"],
        )

        print("\n" + "=" * 65)
        print(f"Case              : {case['name']}")
        print(f"Permission Score  : {case['permission']}")
        print(f"Threat Intel Score: {case['threat_intel']}")
        print(f"Static Code Score : {case['static_code']}")
        print(f"Final Risk Score  : {result['final_score']} / 100")
        print(f"Final Severity    : {result['final_severity']}")
        print(f"Recommendation    : {result['recommendation']}")


if __name__ == "__main__":
    main()