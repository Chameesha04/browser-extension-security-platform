from __future__ import annotations

import json
import platform
import socket
from datetime import datetime
from typing import Any, Iterable, Mapping


class SyslogSendError(RuntimeError):
    """Raised when events cannot be delivered to the Wazuh Syslog listener."""


class SyslogEventSender:
    """Send JSON security events through TCP Syslog."""

    def __init__(
        self,
        server: str,
        port: int = 5514,
        timeout: float = 5.0,
        application_name: str = "chrome-extension-scanner",
    ) -> None:
        if not server.strip():
            raise ValueError("Syslog server address cannot be empty.")

        if not 1 <= port <= 65535:
            raise ValueError("Syslog port must be between 1 and 65535.")

        self.server = server.strip()
        self.port = port
        self.timeout = timeout
        self.application_name = application_name

    def send_events(
        self,
        events: Iterable[Mapping[str, Any]],
    ) -> int:
        event_list = list(events)

        if not event_list:
            return 0

        sent_count = 0

        try:
            with socket.create_connection(
                (self.server, self.port),
                timeout=self.timeout,
            ) as connection:
                for event in event_list:
                    message = self._format_message(event)
                    connection.sendall(message)
                    sent_count += 1

        except (OSError, socket.timeout) as error:
            raise SyslogSendError(
                f"Unable to send Syslog events to "
                f"{self.server}:{self.port}: {error}"
            ) from error

        return sent_count

    def _format_message(
        self,
        event: Mapping[str, Any],
    ) -> bytes:
        timestamp = datetime.now().astimezone().strftime(
            "%b %d %H:%M:%S"
        )

        hostname = str(
            event.get("hostname")
            or platform.node()
            or "unknown-host"
        )

        payload = json.dumps(
            dict(event),
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )

        message = (
            f"{timestamp} "
            f"{hostname} "
            f"{self.application_name}: "
            f"{payload}\n"
        )

        return message.encode("utf-8")