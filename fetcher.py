"""SSRF-safe page fetcher.

Each hop resolves the host once, rejects any non-public address, and pins the
connection to the vetted IP (so DNS rebinding can't swap it afterwards).
Redirects are followed manually and re-checked; body size and total time are capped.
"""
import http.client
import ipaddress
import socket
import time
from urllib.parse import urljoin, urlsplit

import urllib3

MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
DEADLINE_SECONDS = 20
TIMEOUT = urllib3.Timeout(connect=5, read=10)
USER_AGENT = "Mozilla/5.0 (compatible; Linkwise/1.0)"
HTML_TYPES = ("text/html", "application/xhtml+xml")
REDIRECT_CODES = (301, 302, 303, 307, 308)


class FetchError(Exception):
    """Raised with a message that is safe to show to the user."""


def _is_public(ip):
    if ip.version == 6:
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip.sixtofour:
            ip = ip.sixtofour
    return ip.is_global and not ip.is_multicast


def _resolve_public_ip(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise FetchError("Could not resolve the link's host")
    addresses = [ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos]
    if not addresses or not all(_is_public(ip) for ip in addresses):
        raise FetchError("Links to private or internal addresses are not allowed")
    return str(addresses[0])


def _open(url):
    """Issue one GET pinned to a vetted IP. Returns an unread urllib3 response."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise FetchError("Only http and https links are supported")
    host = parts.hostname
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise FetchError("Invalid URL")
    if not host:
        raise FetchError("Invalid URL")

    ip = _resolve_public_ip(host, port)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    headers = {
        "Host": parts.netloc.rpartition("@")[2],  # never forward userinfo
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    }
    if scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            ip, port, timeout=TIMEOUT, retries=False, maxsize=1,
            cert_reqs="CERT_REQUIRED", server_hostname=host, assert_hostname=host,
        )
    else:
        pool = urllib3.HTTPConnectionPool(ip, port, timeout=TIMEOUT, retries=False, maxsize=1)
    try:
        response = pool.urlopen(
            "GET", target, headers=headers, redirect=False,
            preload_content=False, assert_same_host=False,
        )
    except Exception:
        pool.close()
        raise
    return pool, response


def fetch_html(url):
    """Fetch an HTML page and return its (possibly truncated) body as bytes."""
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        for _ in range(MAX_REDIRECTS + 1):
            pool, response = _open(url)
            try:
                if response.status in REDIRECT_CODES:
                    location = response.headers.get("Location")
                    if not location:
                        raise FetchError("Redirect without a destination")
                    url = urljoin(url, location)
                    continue
                if response.status >= 400:
                    raise FetchError(f"The page returned HTTP {response.status}")

                content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if content_type and content_type not in HTML_TYPES:
                    raise FetchError("Only HTML pages can be summarized")

                body = bytearray()
                for chunk in response.stream(64 * 1024, decode_content=True):
                    body += chunk
                    if len(body) >= MAX_BYTES:
                        break
                    if time.monotonic() > deadline:
                        raise FetchError("The page took too long to load")
                return bytes(body[:MAX_BYTES])
            finally:
                response.close()
                pool.close()
        raise FetchError("Too many redirects")
    except FetchError:
        raise
    except (urllib3.exceptions.HTTPError, http.client.HTTPException, OSError, ValueError):
        raise FetchError("Could not fetch the page")
