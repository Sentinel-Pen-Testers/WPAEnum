#!/usr/bin/env python3
"""
Authorized WPA2-Enterprise settings tester.

This script uses NetworkManager's nmcli command to try common WPA2-Enterprise
EAP/phase-2 combinations and username formats against a target SSID. It is
intended for authorized network administration and assessment only.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from rich.text import Text
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()
version = "1.0.0"
HEADER_PRINTED_ENV = "WPAENUM_HEADER_PRINTED"


@dataclass(frozen=True)
class Credential:
    username: str
    password: str


@dataclass(frozen=True)
class EnterpriseMethod:
    label: str
    eap: str
    phase2_auth: str | None = None
    phase2_autheap: str | None = None


@dataclass(frozen=True)
class AttemptResult:
    ssid: str
    identity: str
    password: str
    method: EnterpriseMethod
    success: bool
    message: str


METHODS = (
    EnterpriseMethod("PEAP + MSCHAPV2", "peap", phase2_auth="mschapv2"),
    EnterpriseMethod("TTLS + PAP", "ttls", phase2_auth="pap"),
    EnterpriseMethod("TTLS + MSCHAPV2", "ttls", phase2_auth="mschapv2"),
    EnterpriseMethod("TTLS + GTC", "ttls", phase2_auth="gtc"),
    EnterpriseMethod("PEAP + GTC", "peap", phase2_autheap="gtc"),
)


def run_nmcli(args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nmcli", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def require_nmcli() -> None:
    if shutil.which("nmcli") is None:
        console.print("[bold red]nmcli was not found.[/bold red]")
        console.print("Install and start NetworkManager, then run this script again.")
        sys.exit(2)


def is_elevated() -> bool:
    if hasattr(os, "geteuid"):
        return os.geteuid() == 0
    return True


def ensure_elevated(auto_elevate: bool) -> None:
    if is_elevated():
        return

    if not auto_elevate:
        raise PermissionError(
            "Elevated privileges are required to manage NetworkManager WiFi profiles."
        )

    sudo_path = shutil.which("sudo")
    if not sudo_path:
        raise PermissionError(
            "Elevated privileges are required, but sudo was not found. "
            "Run as root or install sudo."
        )

    console.print(
        "[yellow]Elevated privileges are required to manage NetworkManager WiFi profiles.[/yellow]"
    )
    console.print("[dim]Re-running through sudo; enter your password if prompted.[/dim]")

    command = [sudo_path, f"{HEADER_PRINTED_ENV}=1", sys.executable, *sys.argv]
    try:
        os.execvp(sudo_path, command)
    except OSError as exc:
        raise PermissionError(f"Failed to re-run with sudo: {exc}") from exc


def detect_wifi_interface(provided: str | None) -> str:
    if provided:
        return provided

    result = run_nmcli(["-t", "-f", "DEVICE,TYPE,STATE", "device"], timeout=10)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Unable to list NetworkManager devices.")

    for line in result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] == "wifi":
            return parts[0]

    raise RuntimeError("No WiFi interface was found by NetworkManager.")


def parse_credential_file(path: Path) -> list[Credential]:
    credentials: list[Credential] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            username, separator, password = line.partition(":")
            if not separator or not username or not password:
                raise ValueError(
                    f"{path}:{line_number} must be in username@domain:password format."
                )
            credentials.append(Credential(username=username.strip(), password=password))

    if not credentials:
        raise ValueError(f"{path} did not contain any credentials.")

    return credentials


def parse_credentials(username: str, password: str | None) -> list[Credential]:
    credential_path = Path(username)

    if credential_path.is_file():
        if password:
            console.print(
                "[yellow]Password argument ignored because a credential file was provided.[/yellow]"
            )
        return parse_credential_file(credential_path)

    if not password:
        raise ValueError(
            "Provide a password, or provide a credential file with username@domain:password lines."
        )

    return [Credential(username=username, password=password)]


def username_variants(username: str, auth_domain: str | None = None) -> list[str]:
    local, separator, email_domain = username.partition("@")
    variants = [username]

    if separator and local and email_domain:
        variants = [local, username]

        domain = auth_domain or email_domain
        variants.append(f"{domain}\\{local}")
        if auth_domain:
            variants.append(f"{local}@{auth_domain}")
    elif auth_domain:
        variants.append(f"{auth_domain}\\{username}")
        variants.append(f"{username}@{auth_domain}")

    deduped: list[str] = []
    for variant in variants:
        if variant not in deduped:
            deduped.append(variant)

    return deduped


def build_connection_name(ssid: str) -> str:
    safe_ssid = "".join(char if char.isalnum() else "-" for char in ssid).strip("-")
    safe_ssid = safe_ssid[:32] or "enterprise-wifi"
    return f"wifi-test-{safe_ssid}-{uuid.uuid4().hex[:8]}"


def write_password_file(password: str) -> Path:
    temp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="wifi-enterprise-",
        suffix=".secrets",
        delete=False,
    )
    with temp:
        temp.write(f"802-1x.password:{password}\n")
    return Path(temp.name)


def add_connection(
    connection_name: str,
    ssid: str,
    interface_name: str,
    identity: str,
    method: EnterpriseMethod,
) -> None:
    command = [
        "connection",
        "add",
        "type",
        "wifi",
        "ifname",
        interface_name,
        "con-name",
        connection_name,
        "ssid",
        ssid,
        "--",
        "wifi-sec.key-mgmt",
        "wpa-eap",
        "802-1x.eap",
        method.eap,
        "802-1x.identity",
        identity,
        "802-1x.system-ca-certs",
        "no",
    ]

    if method.phase2_auth:
        command.extend(["802-1x.phase2-auth", method.phase2_auth])
    if method.phase2_autheap:
        command.extend(["802-1x.phase2-autheap", method.phase2_autheap])

    result = run_nmcli(command, timeout=20)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Failed to add profile.")


def cleanup_connection(connection_name: str) -> None:
    run_nmcli(["connection", "down", connection_name], timeout=10)
    run_nmcli(["connection", "delete", connection_name], timeout=10)


def test_login(
    ssid: str,
    interface_name: str,
    identity: str,
    password: str,
    method: EnterpriseMethod,
    activation_timeout: int,
) -> AttemptResult:
    connection_name = build_connection_name(ssid)
    secret_file: Path | None = None

    try:
        add_connection(connection_name, ssid, interface_name, identity, method)
        secret_file = write_password_file(password)
        result = run_nmcli(
            [
                "--ask",
                "connection",
                "up",
                connection_name,
                "ifname",
                interface_name,
                "passwd-file",
                str(secret_file),
            ],
            timeout=activation_timeout,
        )

        output = (result.stdout + "\n" + result.stderr).strip()
        success = result.returncode == 0 and "successfully activated" in output.lower()
        message = output.splitlines()[-1] if output else "No nmcli output."
        return AttemptResult(ssid, identity, password, method, success, message)
    except subprocess.TimeoutExpired:
        return AttemptResult(
            ssid,
            identity,
            password,
            method,
            False,
            f"Activation timed out after {activation_timeout} seconds.",
        )
    except Exception as exc:
        return AttemptResult(ssid, identity, password, method, False, str(exc))
    finally:
        cleanup_connection(connection_name)
        if secret_file and secret_file.exists():
            secret_file.unlink(missing_ok=True)
        time.sleep(1)


def iter_attempts(
    credentials: Iterable[Credential],
    auth_domain: str | None = None,
) -> Iterable[tuple[str, str, EnterpriseMethod]]:
    for credential in credentials:
        for identity in username_variants(credential.username, auth_domain):
            for method in METHODS:
                yield identity, credential.password, method


def print_attempt_result(result: AttemptResult) -> None:
    status = "[bold green]SUCCESS[/bold green]" if result.success else "[red]FAILED[/red]"
    console.print(
        f"{status} [cyan]{result.method.label}[/cyan] "
        f"identity=[bold]{result.identity}[/bold] "
        f"message={result.message}"
    )


def print_summary(results: list[AttemptResult]) -> None:
    successes = [result for result in results if result.success]

    console.print()
    if not successes:
        console.print("[bold red]No successful login attempts were found.[/bold red]")
        return

    table = Table(title="Successful Login Attempts")
    table.add_column("Network", style="cyan")
    table.add_column("Identity", style="green")
    table.add_column("Password", style="yellow")
    table.add_column("Method", style="magenta")

    for result in successes:
        table.add_row(result.ssid, result.identity, result.password, result.method.label)

    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Try common WPA2-Enterprise username formats and EAP settings."
    )
    parser.add_argument("network_name", help="Wireless network SSID to test.")
    parser.add_argument(
        "username",
        help="username@domain, or a file containing username@domain:password lines.",
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password for a single username. Omit this when using a credential file.",
    )
    parser.add_argument(
        "--auth-domain",
        help=(
            "Internal authentication domain to use for domain-qualified identities, "
            "for example city.brentwood-tn.org. Defaults to the email domain when "
            "the username is username@domain."
        ),
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="WiFi interface to use. Defaults to the first NetworkManager WiFi device.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=35,
        help="Seconds to wait for each activation attempt. Default: 35.",
    )
    parser.add_argument(
        "--no-elevate",
        action="store_true",
        help="Do not automatically re-run through sudo when elevated privileges are needed.",
    )
    return parser


def print_beginning(args):
    body = Text()
    body.append("WPAEnum\n", style="bold cyan")
    body.append("Dustin Smith ", style="white")
    body.append("• ", style="dim")
    body.append("Sentinel Technologies\n", style="dim")
    body.append("Luke Lauterbach ", style="white")
    body.append("• ", style="dim")
    body.append("Sentinel Technologies\n", style="dim")
    body.append(f"\nVersion {version}", style="dim")

    Console().print(
        Panel.fit(
            Align.center(body),
            border_style="cyan",
            padding=(0, 2),
        )
    )

    console.print(f"Testing Enterprise WiFi: [bold cyan]{args.network_name}[/bold cyan]")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if os.environ.get(HEADER_PRINTED_ENV) != "1":
        print_beginning(args)

    try:
        require_nmcli()
        credentials = parse_credentials(args.username, args.password)
        ensure_elevated(auto_elevate=not args.no_elevate)
        interface_name = detect_wifi_interface(args.interface)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 2

    console.print(f"Using interface: [cyan]{interface_name}[/cyan]")
    console.print()

    results: list[AttemptResult] = []
    for identity, password, method in iter_attempts(credentials, args.auth_domain):
        status_message = (
            f"Attempting [cyan]{method.label}[/cyan] "
            f"identity=[bold]{identity}[/bold]"
        )
        with console.status(status_message, spinner="dots"):
            result = test_login(
                args.network_name,
                interface_name,
                identity,
                password,
                method,
                args.timeout,
            )
        results.append(result)
        print_attempt_result(result)

    print_summary(results)
    return 0 if any(result.success for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
