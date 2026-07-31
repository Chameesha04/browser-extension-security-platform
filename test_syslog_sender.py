import platform

from endpoint_scanner.syslog_sender import (
    SyslogEventSender,
    SyslogSendError,
)


def main() -> None:
    event = {
        "integration": "chrome_extension_security",
        "event_type": "extension_inventory",
        "hostname": platform.node(),
        "browser": "Chrome",
        "profile": "Default",
        "extension_id": "python-syslog-test",
        "extension_name": "Python Syslog Test Extension",
        "extension_version": "1.0.0",
        "manifest_version": 3,
        "permissions": ["storage"],
        "host_permissions": [],
        "risk_score": None,
        "severity": "unscored",
    }

    sender = SyslogEventSender(
        server="192.168.1.4",
        port=5514,
    )

    try:
        sent_count = sender.send_events([event])
        print(f"{sent_count} Syslog event sent successfully.")

    except SyslogSendError as error:
        print(f"Syslog delivery failed: {error}")


if __name__ == "__main__":
    main()