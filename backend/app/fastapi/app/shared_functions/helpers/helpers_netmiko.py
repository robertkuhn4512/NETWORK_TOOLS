import json
import logging
import time
from typing import Iterable, Any, Dict, List, Optional, Tuple, Union, Iterator
from datetime import datetime, date, timezone
from contextlib import contextmanager
from app.shared_functions.helpers.helpers_logging_config import setup_logging
from app.shared_functions.helpers.helpers_sanitation import scrub_secrets
from netmiko import (
    ReadTimeout,
    ConnectHandler,
    SSHDetect,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    file_transfer,
)

logger = logging.getLogger(__name__)

@contextmanager
def ssh_session(*, enable: bool = True, **connect_args) -> Iterator[Any]:
    """
    Netmiko connection context manager:
    - clean connect / disconnect
    - optional enable mode
    - logs redacted connect args on failures
    """
    start = time.time()
    host = connect_args.get("host")

    try:
        conn = ConnectHandler(**connect_args)
    except NetmikoAuthenticationException as e:
        logger.error("Netmiko auth failed to %s: %s", host, e)
        logger.debug("connect_args=%s", scrub_secrets(connect_args))
        raise
    except NetmikoTimeoutException as e:
        logger.error("Netmiko timeout connecting to %s: %s", host, e)
        logger.debug("connect_args=%s", scrub_secrets(connect_args))
        raise
    except Exception:
        logger.exception("Failed opening SSH to %s", host)
        logger.debug("connect_args=%s", scrub_secrets(connect_args))
        raise

    try:
        # Only attempt enable if requested AND a secret is provided
        if enable and connect_args.get("secret"):
            conn.enable()
        yield conn
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass
        logger.info("SSH session to %s closed after %.1fs", host, time.time() - start)


async def netmiko_autodiscover(
        *,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        enable_secret: Optional[str] = None,
        autodiscover: bool = True,
        device_type: Optional[str] = None,
        command: Optional[str] = None,
        timeout: int = 20,
        conn_timeout: int = 10,
) -> Dict[str, Any]:
    """
    Returns:
      - {"ok": True, "host": ..., "device_type": ..., "output": ...}
      - {"error": "<code>", ...}
    """

    base: Dict[str, Any] = {
        "host": host,
        "username": username,
        "password": password,
        "port": int(port),
        "timeout": int(timeout),
        "conn_timeout": int(conn_timeout),
    }
    if enable_secret:
        base["secret"] = enable_secret

    try:
        detected: Optional[str] = None

        if autodiscover:
            guess = dict(base)
            guess["device_type"] = "autodetect"
            detected = SSHDetect(**guess).autodetect()
            if not detected:
                return {"error": "netmiko_autodetect_failed", "host": host}
            base["device_type"] = detected
        else:
            if not device_type:
                return {"error": "netmiko_device_type_missing", "host": host}
            base["device_type"] = device_type

        # Sending a command is option on discovery.
        # For example show running-config | i ^hostname
        # Or something similar to fetch additional information
        # This can be tied into a specific device type once discovered.
        # for example base["device_type"] -> cisco_ios

        if command is not None:
            # Use the shared context manager for clean session lifecycle
            with ssh_session(enable=bool(enable_secret), **base) as conn:
                output = conn.send_command(command)
        else:
            command = "No commands sent during discovery"
            output = ""

        return {
            "ok": True,
            "host": host,
            "device_type": base["device_type"],
            "detected_device_type": detected,
            "command": command,
            "output": output,
        }

    except NetmikoAuthenticationException as exc:
        return {"error": "netmiko_auth_failed", "host": host, "detail": str(exc)}
    except NetmikoTimeoutException as exc:
        return {"error": "netmiko_timeout", "host": host, "detail": str(exc)}
    except Exception as exc:
        return {"error": "netmiko_unhandled_error", "host": host, "detail": str(exc)}

async def netmiko_fetch_command_output(
    *,
    host: str,
    username: str,
    password: str,
    port: int = 22,
    enable_secret: Optional[str] = None,
    device_type: str,
    command: Union[str, Sequence[str]],
    timeout: int = 20,
    conn_timeout: int = 10,
) -> Dict[str, Any]:
    """
    Fetch output from one or more Netmiko commands.

    command:
      - "show version"
      - ["show version", "show inventory", ...]

    Returns:
      - {"ok": True, "host": ..., "device_type": ..., "commands": [...], "output": "..."}
      - {"error": "<code>", ...}
    """

    if not device_type:
        return {"error": "netmiko_device_type_missing", "host": host}

    if command is None:
        return {"error": "netmiko_no_command_provided", "host": host}

    # Normalize command(s) to a list[str]
    if isinstance(command, str):
        commands: List[str] = [command.strip()]
    else:
        try:
            commands = [str(c).strip() for c in command]  # type: ignore[arg-type]
        except TypeError:
            return {"error": "netmiko_invalid_command_type", "host": host, "detail": f"type={type(command)!r}"}

    commands = [c for c in commands if c]
    if not commands:
        return {"error": "netmiko_no_command_provided", "host": host}

    base: Dict[str, Any] = {
        "host": host,
        "username": username,
        "password": password,
        "port": int(port),
        "timeout": int(timeout),
        "conn_timeout": int(conn_timeout),
        "device_type": device_type,
    }
    if enable_secret:
        base["secret"] = enable_secret

    try:
        # Use the shared context manager for clean session lifecycle
        with ssh_session(enable=bool(enable_secret), **base) as conn:
            combined_output_parts: List[str] = []
            for cmd in commands:
                out = conn.send_command(cmd)
                combined_output_parts.append(f"### COMMAND: {cmd}\n{out}".rstrip())

        combined_output = "\n\n".join(combined_output_parts).strip()

        return {
            "host": host,
            "device_type": device_type,
            "command": commands,
            "output": combined_output,
        }

    except NetmikoAuthenticationException as exc:
        return {"error": "netmiko_auth_failed", "host": host, "detail": str(exc)}
    except NetmikoTimeoutException as exc:
        return {"error": "netmiko_timeout", "host": host, "detail": str(exc)}
    except Exception as exc:
        return {"error": "netmiko_unhandled_error", "host": host, "detail": str(exc)}