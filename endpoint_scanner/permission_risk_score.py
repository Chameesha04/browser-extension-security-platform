
from endpoint_scanner.models import Extension


RISK_MODEL_VERSION = "permission-v1"
# -----------------------------
# Risk weights
# -----------------------------

PERMISSION_WEIGHTS = {
    "tabs": 5,
    "storage": 1,
    "cookies": 15,
    "history": 15,
    "downloads": 10,
    "clipboardRead": 15,
    "clipboardWrite": 5,
    "management": 30,
    "nativeMessaging": 40,
    "webRequest": 20,
    "webRequestBlocking": 25,
    "debugger": 40,
    "proxy": 30,
    "downloads.open": 20,
}


HOST_PERMISSION_WEIGHTS = {
    "<all_urls>": 25,
    "*://*/*": 25
}





def score_extensions(
    extensions: list[Extension],
) -> None:
    """
    Score Extension objects in memory.
    """

    for extension in extensions:
        score, severity, findings = calculate_risk(
            {
                "permissions": extension.permissions,
                "host_permissions": extension.host_permissions,
                "manifest_version": extension.manifest_version,
                "extension_name": extension.name,
                "extension_id": extension.extension_id,
            }
        )

        extension.risk_score = score
        extension.severity = severity
        extension.findings = findings


# -----------------------------
# Calculate risk
# -----------------------------

from typing import Any


def calculate_risk(
    extension: dict[str, Any],
) -> tuple[int, str, list[dict[str, Any]]]:

    score = 0
    findings = []

    # Permissions
    for perm in extension.get("permissions", []):

        if perm in PERMISSION_WEIGHTS:

            value = PERMISSION_WEIGHTS[perm]
            score += value

            findings.append({
                "category": "Permission",
                "item": perm,
                "score": value,
                "reason": f"Uses '{perm}' permission."
            })


    # Host permissions
    for host in extension.get("host_permissions", []):

        if host in HOST_PERMISSION_WEIGHTS:

            value = HOST_PERMISSION_WEIGHTS[host]
            score += value

            findings.append({
                "category": "Host Permission",
                "item": host,
                "score": value,
                "reason": "Can access nearly every website."
            })


    # Manifest version
    if extension.get("manifest_version") == 2:

        score += 10

        findings.append({
            "category": "Manifest",
            "item": "Manifest V2",
            "score": 10,
            "reason": "Manifest V2 is deprecated."
        })


    # Too many permissions
    if len(extension.get("permissions", [])) >= 10:

        score += 10

        findings.append({
            "category": "Permissions",
            "item": "Many Permissions",
            "score": 10,
            "reason": "Requests many permissions."
        })


    # Dangerous combinations

    perms = set(extension.get("permissions", []))


    if {"cookies", "webRequest"} <= perms:

        score += 15

        findings.append({
            "category": "Combination",
            "item": "cookies + webRequest",
            "score": 15,
            "reason": "Can inspect traffic and access cookies."
        })


    if {"management", "nativeMessaging"} <= perms:

        score += 20

        findings.append({
            "category": "Combination",
            "item": "management + nativeMessaging",
            "score": 20,
            "reason": "Can control extensions and communicate with native applications."
        })


    # Maximum score
    score = min(score, 100)


    # Severity
    if score < 20:
        severity = "Low"

    elif score < 50:
        severity = "Medium"

    elif score < 80:
        severity = "High"

    else:
        severity = "Critical"


    # Add results
    return score, severity, findings


# -----------------------------
# Score all extensions
# -----------------------------
