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


try:
    # Newer Netmiko includes this for "command read timed out"
    from netmiko.exceptions import ReadTimeout
except Exception:
    ReadTimeout = None

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
    max_wait_time: int = 120,          # <- NEW (default 120)
    timeout_step: int = 15,            # <- NEW (+15 per retry)
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Call with either a single command or a list of commands:
            res = await netmiko_fetch_command_output(
                host="10.0.0.1",
                username="u",
                password="p",
                device_type="cisco_nxos",
                command=["show version", "show cdp neighbors"],
                timeout=20,
                max_wait_time=120,
            )

      - On timeout failures, the function retries with timeout increased by `timeout_step`
        (default +15s) until it reaches `max_wait_time` (default 120s).

      - Success returns BOTH:
          * res["output"]   -> combined output (single string)
          * res["outputs"]  -> dict mapping each command -> its output

    Returns (success):
      {
        "ok": True,
        "host": "...",
        "device_type": "...",
        "commands": ["...", "..."],
        "output": "<combined string>",
        "outputs": {...},
        "timeout_used": 50,
        "timeouts_tried": [20, 35, 50]
      }

    Returns (error):
      {"error": "<code>", ...}
    """
    if not device_type:
        return {"error": "netmiko_device_type_missing", "host": host}

    if command is None:
        return {"error": "netmiko_no_command_provided", "host": host}

    # Normalize command(s) to list[str]
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

    # Normalize timers
    timeout = int(timeout)
    conn_timeout = int(conn_timeout)
    max_wait_time = int(max_wait_time) if max_wait_time not in (None, 0) else 120
    timeout_step = max(1, int(timeout_step))

    # Ensure the cap isn't lower than the starting timeout
    if max_wait_time < timeout:
        max_wait_time = timeout

    base: Dict[str, Any] = {
        "host": host,
        "username": username,
        "password": password,
        "port": int(port),
        "conn_timeout": conn_timeout,
        "device_type": device_type,
    }
    if enable_secret:
        base["secret"] = enable_secret

    def _run_sync(*, attempt_timeout: int) -> Dict[str, Any]:
        # outputs: command -> output (or list of outputs if cmd repeated)
        outputs_map: Dict[str, Any] = {}
        combined_parts: List[str] = []

        run_base = dict(base)
        run_base["timeout"] = int(attempt_timeout)

        # One session, many commands
        with ssh_session(enable=bool(enable_secret), **run_base) as conn:
            for cmd in commands:
                # Prefer per-command read_timeout if supported by this Netmiko version/driver.
                try:
                    out = conn.send_command(cmd, read_timeout=int(attempt_timeout))
                except TypeError:
                    # Older Netmiko / certain drivers: no read_timeout kwarg
                    out = conn.send_command(cmd)

                if cmd not in outputs_map:
                    outputs_map[cmd] = out
                else:
                    existing = outputs_map[cmd]
                    if isinstance(existing, list):
                        existing.append(out)
                    else:
                        outputs_map[cmd] = [existing, out]

                combined_parts.append(f"### COMMAND: {cmd}\n{out}".rstrip())

        combined_output = "\n\n".join(combined_parts).strip()

        return {
            "ok": True,
            "host": host,
            "device_type": device_type,
            "commands": commands,
            "output": combined_output,
            "outputs": outputs_map,
        }

    async def _run_in_thread(fn):
        try:
            import anyio
            return await anyio.to_thread.run_sync(fn)
        except Exception:
            return fn()

    timeouts_tried: List[int] = []
    attempt_timeout = timeout

    while True:
        timeouts_tried.append(attempt_timeout)

        try:
            res = await _run_in_thread(lambda: _run_sync(attempt_timeout=attempt_timeout))
            # annotate success with retry/timer metadata
            res["timeout_used"] = attempt_timeout
            res["timeouts_tried"] = list(timeouts_tried)
            return res

        except NetmikoAuthenticationException as exc:
            return {"error": "netmiko_auth_failed", "host": host, "detail": str(exc)}

        except NetmikoTimeoutException as exc:
            if attempt_timeout >= max_wait_time:
                return {
                    "error": "netmiko_timeout",
                    "host": host,
                    "detail": str(exc),
                    "timeouts_tried": list(timeouts_tried),
                    "max_wait_time": max_wait_time,
                }
            attempt_timeout = min(attempt_timeout + timeout_step, max_wait_time)
            continue

        except Exception as exc:
            # Also treat Netmiko ReadTimeout (if present) as a retryable timeout
            if ReadTimeout is not None and isinstance(exc, ReadTimeout):  # type: ignore[arg-type]
                if attempt_timeout >= max_wait_time:
                    return {
                        "error": "netmiko_timeout",
                        "host": host,
                        "detail": str(exc),
                        "timeouts_tried": list(timeouts_tried),
                        "max_wait_time": max_wait_time,
                    }
                attempt_timeout = min(attempt_timeout + timeout_step, max_wait_time)
                continue

            return {"error": "netmiko_unhandled_error", "host": host, "detail": str(exc)}