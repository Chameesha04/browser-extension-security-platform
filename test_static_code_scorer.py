import json
from pathlib import Path

from analysis_engine.static_code_scorer import (
    StaticCodeScorer,
)


INPUT_PATH = Path(
    "logs/latest_normalized_ioc_report.json"
)


def main():

    with INPUT_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:

        reports = json.load(file)

    scorer = StaticCodeScorer()

    print(
        "\n===== Static Code Scores ====="
    )

    for report in reports:

        result = scorer.score(
            report
        )

        print(
            "\n"
            + "=" * 65
        )

        print(
            f"Extension : "
            f"{report.get('extension_name')}"
        )

        print(
            f"Score      : "
            f"{result['score']} / 100"
        )

        print(
            f"Severity   : "
            f"{result['severity']}"
        )

        print(
            f"Techniques : "
            f"{result['techniques_detected']}"
        )


if __name__ == "__main__":
    main()