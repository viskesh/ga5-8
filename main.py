"""
Guardrail endpoint for the "Guardrail Red-Team Round-Trip" assignment.

It sits in front of two tools:
  - read_file(path)  -> only allowed inside SANDBOX_ROOT
  - fetch_url(url)   -> only allowed to a fixed host allowlist, with
                        SSRF protections (no private/loopback/link-local/
                        metadata IPs, no userinfo tricks, redirects
                        re-validated hop by hop).
"""

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlsplit, urljoin

import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# ---------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------

SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-8631d06169").resolve()
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 5  # seconds


def block(reason: str):
    return {"action": "block", "reason": reason, "result": None}


def allow(reason: str, result):
    return {"action": "allow", "reason": reason, "result": result}


# ---------------------------------------------------------------------
# read_file guardrail
# ---------------------------------------------------------------------

def handle_read_file(path):
    if not isinstance(path, str) or not path:
        return block("missing or invalid path")

    # Join the requested path under the sandbox root, then .resolve()
    # it. resolve() collapses "..", follows symlinks, and gives us the
    # REAL final location on disk -- not just what the string looks like.
    candidate = (SANDBOX_ROOT / path.lstrip("/")).resolve()

    # relative_to() does a proper path-component comparison (not a
    # naive string prefix check), so "sandbox-8631d06169-evil" can't
    # slip past just because it starts with the same characters.
    try:
        candidate.relative_to(SANDBOX_ROOT)
    except ValueError:
        return block("path escapes sandbox root")

    if not candidate.exists() or not candidate.is_file():
        return block("file not found")

    try:
        content = candidate.read_text(errors="replace")
    except OSError:
        return block("could not read file")

    return allow("path resolves inside sandbox root", content)


# ---------------------------------------------------------------------
# fetch_url guardrail
# ---------------------------------------------------------------------

def is_disallowed_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparsable -> block, don't guess

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True

    # Cloud metadata endpoint (technically link-local, checked
    # explicitly to make the intent obvious).
    if str(ip) == "169.254.169.254":
        return True

    return False


def resolve_all_ips(hostname: str):
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    return list({info[4][0] for info in infos})


def hostname_and_ips_ok(hostname: str):
    if hostname not in ALLOWED_HOSTS:
        return False, "host not in allowlist"

    ips = resolve_all_ips(hostname)
    if not ips:
        return False, "could not resolve host"

    for ip in ips:
        if is_disallowed_ip(ip):
            return False, "host resolves to a disallowed address"

    return True, "ok"


def validate_url(url: str):
    parts = urlsplit(url)

    if parts.scheme not in ("http", "https"):
        return False, "scheme not allowed"

    # "userinfo-confused" hosts: http://example.com@evil.com/ -- a
    # naive parser might think the host is example.com, but the real
    # host is whatever is after the @. Just reject any userinfo.
    if parts.username is not None or parts.password is not None:
        return False, "userinfo in URL not allowed"

    hostname = parts.hostname
    if not hostname:
        return False, "no hostname"

    # Exact-match comparison (after lowercasing / trimming a trailing
    # dot) is what blocks lookalikes like "example.com.evil.com" or
    # homograph domains -- they simply aren't in ALLOWED_HOSTS.
    hostname = hostname.lower().rstrip(".")

    return hostname_and_ips_ok(hostname)


def handle_fetch_url(url):
    if not isinstance(url, str) or not url:
        return block("missing or invalid url")

    ok, reason = validate_url(url)
    if not ok:
        return block(reason)

    # Fetch manually with redirects OFF, and re-validate every hop
    # ourselves. This is what stops "redirect-to-private": the first
    # URL is allowed, but it 302's somewhere we must not follow blindly.
    current_url = url
    for _ in range(MAX_REDIRECTS):
        try:
            resp = requests.get(
                current_url, timeout=REQUEST_TIMEOUT, allow_redirects=False
            )
        except requests.RequestException:
            return block("fetch failed")

        if resp.is_redirect or resp.is_permanent_redirect:
            location = resp.headers.get("Location")
            if not location:
                return block("redirect with no location header")

            next_url = urljoin(current_url, location)
            ok, reason = validate_url(next_url)
            if not ok:
                return block(f"redirect target blocked: {reason}")

            current_url = next_url
            continue

        return allow("host is on allowlist and resolves to a safe address", resp.text)

    return block("too many redirects")


# ---------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------

@app.get("/")
async def health():
    return {"status": "ok"}


@app.post("/")
async def guardrail(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(block("invalid JSON body"))

    if not isinstance(body, dict):
        return JSONResponse(block("invalid request body"))

    tool = body.get("tool")
    arguments = body.get("arguments") or {}
    if not isinstance(arguments, dict):
        arguments = {}

    if tool == "read_file":
        result = handle_read_file(arguments.get("path"))
    elif tool == "fetch_url":
        result = handle_fetch_url(arguments.get("url"))
    else:
        result = block("unknown tool")

    return JSONResponse(result)
