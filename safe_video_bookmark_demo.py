from __future__ import annotations

import argparse
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from analysis_engine.extension_analyzer import ExtensionAnalyzer
from analysis_engine.threat_intel_service import ThreatIntelService
from endpoint_scanner.event_writer import JsonLinesEventWriter
from endpoint_scanner.ioc_extractor import IOCExtractor
from endpoint_scanner.ioc_normalizer import IOCNormalizer
from endpoint_scanner.models import Extension
from endpoint_scanner.permission_risk_score import score_extensions
from endpoint_scanner.syslog_sender import SyslogEventSender, SyslogSendError


DEMO_EXTENSION_ID = "safe-video-bookmark-demo"
DEMO_PROFILE = "Safe Demo"

# SHA-256 of the standard EICAR antivirus test file. This package contains
# only the hash; it does not contain the EICAR test-file bytes.
EICAR_SHA256 = (
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
)

VT_CACHE_PATH = Path("logs/threat_intel_cache/virustotal.json")
EVENT_PREVIEW_PATH = Path("logs/safe_video_bookmark_demo_event.json")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a safe, hash-only VirusTotal and Wazuh demonstration for "
            "the Video Bookmark extension."
        )
    )
    parser.add_argument(
        "--send",
        action="store_true",
        help="Send the generated event to the configured Wazuh TCP listener.",
    )
    parser.add_argument(
        "--refresh-vt-cache",
        action="store_true",
        help=(
            "Back up the VirusTotal cache and remove only the EICAR hash "
            "entry before performing the lookup."
        ),
    )
    return parser.parse_args()


def load_demo_extension(extension_path: Path) -> Extension:
    manifest_path = extension_path / "manifest.json"

    if not manifest_path.is_file():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    return Extension(
        browser="Chrome",
        profile=DEMO_PROFILE,
        extension_id=DEMO_EXTENSION_ID,
        version=str(manifest.get("version", "1.0.0")),
        path=extension_path,
        name=str(manifest.get("name", "Video Bookmark Safe Demo")),
        description=str(manifest.get("description", "")),
        manifest_version=int(manifest.get("manifest_version", 3)),
        permissions=list(manifest.get("permissions", [])),
        host_permissions=list(manifest.get("host_permissions", [])),
        action=dict(manifest.get("action", {})),
    )


def remove_only_demo_cache_entry() -> Path | None:
    if not VT_CACHE_PATH.is_file():
        return None

    try:
        cache = json.loads(VT_CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Could not read VirusTotal cache: {error}") from error

    if not isinstance(cache, dict):
        raise RuntimeError("VirusTotal cache is not a JSON object.")

    cache_key = f"file_hash:{EICAR_SHA256}"

    if cache_key not in cache:
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = VT_CACHE_PATH.with_name(
        f"virustotal.before_safe_demo_{timestamp}.json"
    )
    shutil.copy2(VT_CACHE_PATH, backup_path)

    cache.pop(cache_key)

    temporary_path = VT_CACHE_PATH.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(cache, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    temporary_path.replace(VT_CACHE_PATH)

    return backup_path


def add_safe_test_hash(normalized_report: dict[str, Any]) -> None:
    candidates = normalized_report.setdefault("threat_intel_candidates", {})
    file_hashes = candidates.setdefault("file_hashes", [])

    # Insert first because the production ThreatIntelService checks a bounded
    # number of hashes. The marker is explicit so this cannot be confused with
    # a file actually found inside the extension.
    file_hashes.insert(
        0,
        {
            "file": "[SAFE TEST FIXTURE - HASH ONLY]",
            "sha256": EICAR_SHA256,
            "file_type": "test_fixture",
            "size_bytes": 0,
            "safe_test_fixture": True,
        },
    )

    summary = normalized_report.setdefault("summary", {})
    summary["hash_candidates"] = len(file_hashes)
    summary["safe_test_hash_candidates"] = 1


def build_analysis_result(extension: Extension) -> dict[str, Any]:
    extractor = IOCExtractor()
    normalizer = IOCNormalizer()

    raw_report = extractor.extract(
        extension_path=extension.path,
        extension_id=extension.extension_id,
    )
    raw_report["extension_name"] = extension.name
    raw_report["extension_version"] = extension.version
    raw_report["profile"] = extension.profile

    normalized_report = normalizer.normalize_report(raw_report)
    add_safe_test_hash(normalized_report)

    # The demo deliberately checks only the safe test hash. It does not upload
    # any file or submit URLs to VirusTotal.
    threat_intel_service = ThreatIntelService(
        maximum_domains=0,
        maximum_urls=0,
        maximum_hashes=1,
        maximum_ips=0,
    )
    threat_intel_report = threat_intel_service.enrich(normalized_report)

    if not threat_intel_report.get("lookups"):
        errors = threat_intel_report.get("errors", [])
        raise RuntimeError(f"VirusTotal did not return a report: {errors}")

    assessment = ExtensionAnalyzer().analyze(
        permission_score=int(extension.risk_score or 0),
        normalized_report=normalized_report,
        threat_intel_report=threat_intel_report,
    )

    return {
        "analysis_status": "complete",
        "profiles": [extension.profile],
        "extension_path": str(extension.path),
        "ioc_summary": normalized_report.get("summary", {}),
        "threat_intel_summary": threat_intel_report.get("summary", {}),
        "assessment": assessment,
    }


def create_demo_scan(extension: Extension, analysis_result: dict[str, Any]) -> dict:
    writer = JsonLinesEventWriter()
    analysis_key = f"{extension.extension_id}:{extension.version}"

    scan_result = writer.prepare_scan(
        extensions=[extension],
        changes={"installed": [], "updated": [], "removed": []},
        analysis_results={analysis_key: analysis_result},
    )

    for event in scan_result["events"]:
        event["demo_mode"] = True
        event["test_indicator"] = "EICAR hash-only safe test fixture"
        event["test_indicator_sha256"] = EICAR_SHA256
        event["test_notice"] = (
            "Benign extension; no EICAR bytes or malware are included."
        )

    return scan_result


def save_preview(scan_result: dict) -> None:
    EVENT_PREVIEW_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVENT_PREVIEW_PATH.write_text(
        json.dumps(scan_result["events"], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def display_result(extension: Extension, analysis_result: dict[str, Any]) -> None:
    assessment = analysis_result["assessment"]
    threat = assessment["threat_intelligence_analysis"]
    final = assessment["final_assessment"]

    print("\n===== Safe Video Bookmark Detection Demo =====")
    print(f"Extension            : {extension.name}")
    print("Demo mode            : True")
    print("Indicator type       : EICAR hash-only test fixture")
    print(f"Permission score     : {extension.risk_score}")
    print(f"Threat intel score   : {threat.get('score', 0)}")
    print(
        "VirusTotal malicious : "
        f"{threat.get('total_malicious_engine_detections', 0)}"
    )
    print(f"Final score          : {final.get('final_score', 0)}")
    print(f"Final severity       : {final.get('final_severity', 'unknown')}")
    print(f"Recommendation       : {final.get('recommendation', '')}")
    print(f"Event preview        : {EVENT_PREVIEW_PATH.resolve()}")


def send_to_wazuh(scan_result: dict) -> None:
    host = os.getenv("WAZUH_SYSLOG_HOST", "").strip()
    port_text = os.getenv("WAZUH_SYSLOG_PORT", "5514").strip()

    if not host:
        raise RuntimeError(
            "WAZUH_SYSLOG_HOST is required when --send is used."
        )

    try:
        port = int(port_text)
    except ValueError as error:
        raise RuntimeError("WAZUH_SYSLOG_PORT must be an integer.") from error

    sender = SyslogEventSender(server=host, port=port)
    writer = JsonLinesEventWriter()

    try:
        sent_count = sender.send_events(scan_result["events"])
    except SyslogSendError:
        fallback_path = writer.write_fallback_spool(scan_result)
        print(f"Wazuh delivery failed; fallback written to: {fallback_path.resolve()}")
        raise

    print(f"Successfully sent {sent_count} safe demo event to {host}:{port}.")


def main() -> None:
    args = parse_arguments()

    if not os.getenv("VT_API_KEY", "").strip():
        raise RuntimeError("VT_API_KEY is not configured in this terminal.")

    if args.refresh_vt_cache:
        backup_path = remove_only_demo_cache_entry()
        if backup_path:
            print(f"Backed up VirusTotal cache to: {backup_path.resolve()}")
        else:
            print("The EICAR demo entry was not present in the local cache.")

    project_root = Path(__file__).resolve().parent
    extension_path = (
        project_root / "demo_extensions" / "video_bookmark_safe_demo"
    )

    extension = load_demo_extension(extension_path)
    score_extensions([extension])

    analysis_result = build_analysis_result(extension)
    scan_result = create_demo_scan(extension, analysis_result)
    save_preview(scan_result)
    display_result(extension, analysis_result)

    if args.send:
        send_to_wazuh(scan_result)
    else:
        print("\nPreview only. Add --send when you are ready to forward it to Wazuh.")


if __name__ == "__main__":
    main()
