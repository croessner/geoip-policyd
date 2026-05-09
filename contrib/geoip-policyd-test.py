#!/usr/bin/env python3
"""Exercise geoip-policyd HTTP and Postfix policy endpoints."""

from __future__ import annotations

import argparse
import base64
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence


DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_POLICY_HOST = "127.0.0.1"
DEFAULT_POLICY_PORT = 4646
DEFAULT_TIMEOUT = 10.0
DEFAULT_SENDER = "geoip-policyd-test@example.com"
DEFAULT_CLIENT_ADDRESS = "127.0.0.1"
DEFAULT_RECIPIENT = "postmaster@example.com"


@dataclass
class EndpointResult:
    """EndpointResult stores one endpoint check and its normalized outcome."""

    name: str
    method: str
    target: str
    expected: str
    ok: bool
    status: Optional[int] = None
    body: str = ""
    body_json: Any = None
    error: Optional[str] = None

    def status_label(self) -> str:
        """Return a printable HTTP status or transport status placeholder."""
        if self.status is None:
            return "-"

        return str(self.status)


class GeoIPPolicyHTTPClient:
    """GeoIPPolicyHTTPClient sends JSON requests to the REST interface."""

    def __init__(
        self,
        base_url: str,
        timeout: float,
        username: str,
        password: str,
        insecure_tls: bool,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.username = username
        self.password = password
        self.insecure_tls = insecure_tls

    def request(
        self,
        name: str,
        method: str,
        path: str,
        expected_statuses: Sequence[int],
        payload: Any = None,
        query: Optional[dict[str, str]] = None,
    ) -> EndpointResult:
        """Send one HTTP request and normalize success, status, body, and error."""
        url = self._url(path, query)
        headers = {"Accept": "application/json"}
        data = None

        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"

        if self.username or self.password:
            token = f"{self.username}:{self.password}".encode("utf-8")
            headers["Authorization"] = "Basic " + base64.b64encode(token).decode("ascii")

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        expected = ",".join(str(status) for status in expected_statuses)

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=self._ssl_context(),
            ) as response:
                body = response.read().decode("utf-8", errors="replace")
                status = response.status
                return self._result(name, method, path, expected, expected_statuses, status, body)
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", errors="replace")
            result = self._result(name, method, path, expected, expected_statuses, err.code, body)
            result.error = str(err.reason)

            return result
        except urllib.error.URLError as err:
            return EndpointResult(
                name=name,
                method=method,
                target=path,
                expected=expected,
                ok=False,
                error=str(err.reason),
            )
        except TimeoutError as err:
            return EndpointResult(
                name=name,
                method=method,
                target=path,
                expected=expected,
                ok=False,
                error=str(err),
            )

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        """Return an optional TLS context for HTTPS calls."""
        if self.insecure_tls:
            return ssl._create_unverified_context()

        return None

    def _url(self, path: str, query: Optional[dict[str, str]]) -> str:
        """Build an absolute endpoint URL from the base URL and query parameters."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        return url

    def _result(
        self,
        name: str,
        method: str,
        path: str,
        expected: str,
        expected_statuses: Sequence[int],
        status: int,
        body: str,
    ) -> EndpointResult:
        """Build an EndpointResult and parse JSON bodies when present."""
        parsed_body = None
        if body:
            try:
                parsed_body = json.loads(body)
            except json.JSONDecodeError:
                parsed_body = None

        return EndpointResult(
            name=name,
            method=method,
            target=path,
            expected=expected,
            ok=status in expected_statuses,
            status=status,
            body=body,
            body_json=parsed_body,
        )


class PostfixPolicyClient:
    """PostfixPolicyClient exercises the raw smtpd_access_policy socket."""

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(
        self,
        sender: str,
        client_address: str,
        recipient: str,
        sasl_username: str,
    ) -> EndpointResult:
        """Send one Postfix policy request and expect an action response."""
        target = f"{self.host}:{self.port}"
        payload = self._payload(sender, client_address, recipient, sasl_username)

        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(payload.encode("utf-8"))
                body = self._read_response(sock)
        except OSError as err:
            return EndpointResult(
                name="policy",
                method="TCP",
                target=target,
                expected="action=*",
                ok=False,
                error=str(err),
            )

        return EndpointResult(
            name="policy",
            method="TCP",
            target=target,
            expected="action=*",
            ok=body.startswith("action="),
            body=body,
        )

    def _payload(
        self,
        sender: str,
        client_address: str,
        recipient: str,
        sasl_username: str,
    ) -> str:
        """Create a minimal Postfix smtpd_access_policy request."""
        lines = [
            "request=smtpd_access_policy",
            "protocol_state=RCPT",
            "protocol_name=ESMTP",
            "helo_name=client.example.test",
            f"sender={sender}",
            f"sasl_username={sasl_username or sender}",
            f"recipient={recipient}",
            f"client_address={client_address}",
            "client_name=client.example.test",
            "",
            "",
        ]

        return "\n".join(lines)

    def _read_response(self, sock: socket.socket) -> str:
        """Read the policy response until the blank-line terminator or EOF."""
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break

            chunks.append(chunk)
            if b"\n\n" in b"".join(chunks):
                break

        return b"".join(chunks).decode("utf-8", errors="replace").strip()


class EndpointRunner:
    """EndpointRunner maps subcommands to concrete geoip-policyd checks."""

    def __init__(self, http: GeoIPPolicyHTTPClient, policy: PostfixPolicyClient) -> None:
        self.http = http
        self.policy = policy

    def reload(self) -> EndpointResult:
        """Check GET /reload."""
        return self.http.request("reload", "GET", "/reload", (202,))

    def custom_settings(self) -> EndpointResult:
        """Check GET /custom-settings."""
        return self.http.request("custom-settings", "GET", "/custom-settings", (200, 204))

    def unlock(self, sender: str) -> EndpointResult:
        """Check POST /remove by unlocking a sender in Redis."""
        return self.http.request(
            "unlock",
            "POST",
            "/remove",
            (202,),
            payload={"key": "sender", "value": sender},
        )

    def query(self, sender: str, client_address: str, compact: bool, info: bool) -> EndpointResult:
        """Check POST /query with a client address and sender."""
        query = {}
        if compact:
            query["compact"] = "1"
        if info:
            query["info"] = "1"

        return self.http.request(
            "query",
            "POST",
            "/query",
            (202,),
            payload={"key": "client", "value": {"address": client_address, "sender": sender}},
            query=query,
        )

    def dovecotpolicy(
        self,
        command: str,
        login: str,
        remote: str,
    ) -> EndpointResult:
        """Check POST /dovecotpolicy with command=allow or command=report."""
        return self.http.request(
            "dovecotpolicy",
            "POST",
            "/dovecotpolicy",
            (200,),
            payload={
                "login": login,
                "remote": remote,
                "protocol": "imap",
                "success": True,
                "tls": True,
            },
            query={"command": command},
        )

    def update(self, payload: dict[str, Any]) -> EndpointResult:
        """Check PUT /update with a custom settings payload."""
        return self.http.request("update", "PUT", "/update", (202,), payload=payload)

    def modify(self, payload: dict[str, Any]) -> EndpointResult:
        """Check PATCH /modify with a sender settings payload."""
        return self.http.request("modify", "PATCH", "/modify", (202,), payload=payload)

    def delete(self, sender: str) -> EndpointResult:
        """Check DELETE /remove by deleting a sender from custom settings."""
        return self.http.request(
            "delete",
            "DELETE",
            "/remove",
            (202,),
            payload={"key": "sender", "value": sender},
        )

    def postfix_policy(
        self,
        sender: str,
        client_address: str,
        recipient: str,
        sasl_username: str,
    ) -> EndpointResult:
        """Check the raw Postfix policy TCP endpoint."""
        return self.policy.request(sender, client_address, recipient, sasl_username)


class ResultPrinter:
    """ResultPrinter renders endpoint results for humans and CI logs."""

    def print_one(self, result: EndpointResult) -> None:
        """Print one detailed command result."""
        self.print_summary([result])
        self._print_body(result)

    def print_summary(self, results: Sequence[EndpointResult]) -> None:
        """Print a compact fixed-width result table."""
        rows = [
            (
                "check",
                "method",
                "target",
                "status",
                "expected",
                "result",
                "summary",
            )
        ]
        for result in results:
            rows.append(
                (
                    result.name,
                    result.method,
                    result.target,
                    result.status_label(),
                    result.expected,
                    "OK" if result.ok else "FAIL",
                    self._summary(result),
                )
            )

        widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
        for index, row in enumerate(rows):
            line = "  ".join(value.ljust(widths[column]) for column, value in enumerate(row))
            print(line)
            if index == 0:
                print("  ".join("-" * width for width in widths))

    def print_failures(self, results: Sequence[EndpointResult]) -> None:
        """Print detailed bodies for failed checks."""
        failures = [result for result in results if not result.ok]
        if not failures:
            return

        print()
        print("Failure details:")
        for result in failures:
            self._print_body(result)

    def _summary(self, result: EndpointResult) -> str:
        """Return a one-line body or transport summary."""
        if result.error:
            return result.error

        body_json = result.body_json
        if isinstance(body_json, dict):
            parts = []
            for key in ("result", "operation", "status", "msg"):
                if key in body_json:
                    parts.append(f"{key}={body_json[key]}")

            obj = body_json.get("object")
            if isinstance(obj, dict):
                if "policy_reject" in obj:
                    parts.append(f"policy_reject={obj['policy_reject']}")
                if "current_country_code" in obj:
                    parts.append(f"country={obj['current_country_code'] or '-'}")

            return ", ".join(parts) if parts else "json object"

        if isinstance(body_json, list):
            return f"{len(body_json)} item(s)"

        if result.body:
            return " ".join(result.body.split())

        return "-"

    def _print_body(self, result: EndpointResult) -> None:
        """Print a response body in a readable form."""
        print()
        print(f"{result.name}:")
        if result.error:
            print(f"error: {result.error}")

        if result.body_json is not None:
            print(json.dumps(result.body_json, indent=2, sort_keys=True))
        elif result.body:
            print(result.body)
        else:
            print("<empty body>")


def default_update_payload(sender: str) -> dict[str, Any]:
    """Return a small custom-settings payload for PUT /update."""
    return {
        "data": [
            {
                "comment": "Temporary geoip-policyd endpoint test account",
                "sender": sender,
                "ips": 10,
                "countries": 3,
            }
        ]
    }


def default_modify_payload(sender: str, comment: str, ips: int, countries: int) -> dict[str, Any]:
    """Return a sender-scoped payload for PATCH /modify."""
    return {
        "key": "sender",
        "value": {
            "comment": comment,
            "sender": sender,
            "ips": ips,
            "countries": countries,
        },
    }


def load_json_file(path: Path) -> dict[str, Any]:
    """Load a JSON object from a file path for mutating endpoint commands."""
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")

    return data


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser and endpoint subcommands."""
    parser = argparse.ArgumentParser(
        description="Test geoip-policyd REST endpoints and the Postfix policy socket.",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"REST base URL (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--policy-host", default=DEFAULT_POLICY_HOST, help=f"Policy host (default: {DEFAULT_POLICY_HOST})")
    parser.add_argument("--policy-port", type=int, default=DEFAULT_POLICY_PORT, help=f"Policy port (default: {DEFAULT_POLICY_PORT})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--username", default="", help="HTTP basic-auth username")
    parser.add_argument("--password", default="", help="HTTP basic-auth password")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate validation for HTTPS tests")
    parser.add_argument("--sender", default=DEFAULT_SENDER, help=f"Sender used by default payloads (default: {DEFAULT_SENDER})")
    parser.add_argument("--address", default=DEFAULT_CLIENT_ADDRESS, help=f"Client IP used by default payloads (default: {DEFAULT_CLIENT_ADDRESS})")
    parser.add_argument("--recipient", default=DEFAULT_RECIPIENT, help=f"Recipient used by policy tests (default: {DEFAULT_RECIPIENT})")
    parser.add_argument("--sasl-username", default="", help="SASL username used by the raw Postfix policy request")

    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("reload", help="GET /reload")
    subcommands.add_parser("custom-settings", help="GET /custom-settings")
    subcommands.add_parser("unlock", aliases=["post-remove"], help="POST /remove")

    query = subcommands.add_parser("query", help="POST /query")
    query.add_argument("--compact", action="store_true", help="Append compact=1")
    query.add_argument("--info", action="store_true", help="Append info=1")

    dovecot = subcommands.add_parser("dovecotpolicy", help="POST /dovecotpolicy")
    dovecot.add_argument(
        "--command",
        dest="dovecot_command",
        choices=("allow", "report"),
        default="allow",
        help="Dovecot policy command",
    )
    dovecot.add_argument("--login", default=None, help="Dovecot login value; defaults to --sender")
    dovecot.add_argument("--remote", default=None, help="Dovecot remote IP; defaults to --address")

    update = subcommands.add_parser("update", help="PUT /update")
    update.add_argument("--payload-file", type=Path, help="JSON file to use instead of the default update payload")

    modify = subcommands.add_parser("modify", help="PATCH /modify")
    modify.add_argument("--payload-file", type=Path, help="JSON file to use instead of the default modify payload")
    modify.add_argument("--comment", default="Modified by geoip-policyd endpoint test", help="Default modify comment")
    modify.add_argument("--ips", type=int, default=12, help="Default modify IP limit")
    modify.add_argument("--countries", type=int, default=4, help="Default modify country limit")

    subcommands.add_parser("delete", aliases=["delete-remove"], help="DELETE /remove")
    subcommands.add_parser("policy", help="Raw Postfix smtpd_access_policy socket")
    subcommands.add_parser("all", help="Run all endpoint checks, including mutating custom-settings checks")

    return parser


def build_runner(args: argparse.Namespace) -> EndpointRunner:
    """Create endpoint runner dependencies from parsed arguments."""
    http = GeoIPPolicyHTTPClient(
        base_url=args.base_url,
        timeout=args.timeout,
        username=args.username,
        password=args.password,
        insecure_tls=args.insecure,
    )
    policy = PostfixPolicyClient(args.policy_host, args.policy_port, args.timeout)

    return EndpointRunner(http, policy)


def dispatch(args: argparse.Namespace, runner: EndpointRunner) -> list[EndpointResult]:
    """Dispatch a parsed subcommand to one or more endpoint checks."""
    if args.command == "reload":
        return [runner.reload()]

    if args.command == "custom-settings":
        return [runner.custom_settings()]

    if args.command in ("unlock", "post-remove"):
        return [runner.unlock(args.sender)]

    if args.command == "query":
        return [runner.query(args.sender, args.address, args.compact, args.info)]

    if args.command == "dovecotpolicy":
        return [
            runner.dovecotpolicy(
                args.dovecot_command,
                args.login or args.sender,
                args.remote or args.address,
            )
        ]

    if args.command == "update":
        payload = load_json_file(args.payload_file) if args.payload_file else default_update_payload(args.sender)
        return [runner.update(payload)]

    if args.command == "modify":
        payload = (
            load_json_file(args.payload_file)
            if args.payload_file
            else default_modify_payload(args.sender, args.comment, args.ips, args.countries)
        )
        return [runner.modify(payload)]

    if args.command in ("delete", "delete-remove"):
        return [runner.delete(args.sender)]

    if args.command == "policy":
        return [runner.postfix_policy(args.sender, args.address, args.recipient, args.sasl_username)]

    if args.command == "all":
        return run_all(args, runner)

    raise ValueError(f"unsupported command: {args.command}")


def run_all(args: argparse.Namespace, runner: EndpointRunner) -> list[EndpointResult]:
    """Run the full endpoint suite with one isolated sender value."""
    return [
        runner.custom_settings(),
        runner.query(args.sender, args.address, compact=False, info=False),
        runner.dovecotpolicy("report", args.sender, args.address),
        runner.dovecotpolicy("allow", args.sender, args.address),
        runner.postfix_policy(args.sender, args.address, args.recipient, args.sasl_username),
        runner.update(default_update_payload(args.sender)),
        runner.modify(default_modify_payload(args.sender, "Modified by geoip-policyd endpoint test", 12, 4)),
        runner.delete(args.sender),
        runner.unlock(args.sender),
        runner.reload(),
    ]


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments, run endpoint checks, print results, and return an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    runner = build_runner(args)
    printer = ResultPrinter()

    try:
        results = dispatch(args, runner)
    except (OSError, ValueError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)

        return 2

    if len(results) == 1:
        printer.print_one(results[0])
    else:
        printer.print_summary(results)
        printer.print_failures(results)

    return 0 if all(result.ok for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
