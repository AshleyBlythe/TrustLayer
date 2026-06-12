"""URL scanner: bounded, GET-only, same-origin crawler.

Intended for scanning preview deployments only.  This is NOT a security
audit tool and should not be exposed as a hosted service without additional
SSRF and abuse protections.

Usage policy:
- GET requests only; no form submissions, no mutations
- Same-origin by default; cross-origin redirects are noted but not followed
- Bounded by MAX_PAGES and MAX_DEPTH
- Recognisable User-Agent so site owners can identify the traffic
- Respects connect timeout to avoid hanging on slow hosts
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from typing import List, Optional

from .checks import check_admin_routes, check_api_docs, check_cors, check_debug_routes, check_secrets
from .models import Confidence, Finding, ScanResult, Severity
from .redaction import redact

MAX_PAGES = 50
MAX_DEPTH = 3
CONNECT_TIMEOUT = 10  # seconds
MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MB per page
USER_AGENT = "TrustLayer-Scanner/0.1 (build-readiness; not a vulnerability scanner)"

_LINK_RE = re.compile(r'href=["\']([^"\'#?][^"\']*)["\']', re.IGNORECASE)
_HEADER_CHECKS = {
    "access-control-allow-origin": ("CORS-001", "Permissive CORS header on URL", Severity.MEDIUM),
    "server": ("URL-010", "Server version disclosure header", Severity.INFO),
    "x-powered-by": ("URL-011", "X-Powered-By header discloses technology stack", Severity.INFO),
}


def _same_origin(base: str, url: str) -> bool:
    b = urllib.parse.urlparse(base)
    u = urllib.parse.urlparse(url)
    return b.scheme == u.scheme and b.netloc == u.netloc


def _normalise_url(base: str, href: str) -> Optional[str]:
    try:
        joined = urllib.parse.urljoin(base, href)
        parsed = urllib.parse.urlparse(joined)
        # Strip fragments and only keep http/https
        if parsed.scheme not in ("http", "https"):
            return None
        clean = parsed._replace(fragment="").geturl()
        return clean
    except Exception:
        return None


def scan_url(start_url: str, result: Optional[ScanResult] = None) -> ScanResult:
    if result is None:
        result = ScanResult(target=start_url, url_scan_enabled=True)
    else:
        result.url_scan_enabled = True

    # queue items: (url, depth)
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    visited: set[str] = set()

    while queue and len(visited) < MAX_PAGES:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=CONNECT_TIMEOUT) as resp:
                # Check for cross-origin redirect
                final_url: str = resp.geturl()
                if not _same_origin(start_url, final_url):
                    result.findings.append(Finding(
                        check_id="URL-001",
                        title="Cross-origin redirect detected",
                        severity=Severity.INFO,
                        confidence=Confidence.OBSERVED,
                        explanation=(
                            f"Request to {url!r} was redirected to a different origin "
                            f"({urllib.parse.urlparse(final_url).netloc}). "
                            "TrustLayer did not follow this redirect."
                        ),
                        who_could_use="N/A — informational",
                        what_they_access="N/A",
                        possible_damage="Potential open redirect if user-controlled",
                        likelihood="Low",
                        fastest_fix="Audit redirect logic to ensure destinations are allow-listed",
                        ask_human=False,
                        evidence=f"From: {url}\nTo: {redact(final_url)}",
                        source=url,
                    ))
                    result.scanned_urls += 1
                    continue

                # Response-size guard
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    result.errors.append(f"Response too large, truncated: {url}")
                    raw = raw[:MAX_RESPONSE_BYTES]

                content_type = resp.headers.get("Content-Type", "")
                headers = dict(resp.headers)

                # Header checks
                for header_name, (check_id, title, severity) in _HEADER_CHECKS.items():
                    value = resp.headers.get(header_name, "")
                    if header_name == "access-control-allow-origin" and value == "*":
                        result.findings.append(Finding(
                            check_id=check_id,
                            title=title,
                            severity=severity,
                            confidence=Confidence.OBSERVED,
                            explanation="Wildcard CORS header observed on this URL.",
                            who_could_use="Any website the user visits",
                            what_they_access="Data from cross-origin requests",
                            possible_damage="Data theft via cross-origin requests",
                            likelihood="Medium",
                            fastest_fix="Restrict CORS to known origins",
                            ask_human=True,
                            evidence=f"Access-Control-Allow-Origin: {value}",
                            source=url,
                        ))
                    elif header_name in ("server", "x-powered-by") and value:
                        result.findings.append(Finding(
                            check_id=check_id,
                            title=title,
                            severity=severity,
                            confidence=Confidence.OBSERVED,
                            explanation=(
                                f"The response includes a {header_name!r} header that "
                                "discloses technology stack information."
                            ),
                            who_could_use="Attackers targeting specific versions",
                            what_they_access="Server software and version details",
                            possible_damage="Easier targeted exploitation of known CVEs",
                            likelihood="Low direct risk",
                            fastest_fix=f"Configure server to omit or genericise {header_name!r}",
                            ask_human=False,
                            evidence=f"{header_name}: {value}",
                            source=url,
                        ))

                result.scanned_urls += 1

                # Only parse HTML for links
                if "html" not in content_type.lower():
                    continue

                try:
                    body = raw.decode("utf-8", errors="replace")
                except Exception:
                    continue

                # Run content checks on the page body
                lines = body.splitlines()
                result.findings.extend(check_secrets(lines, url))
                result.findings.extend(check_cors(lines, url))
                result.findings.extend(check_admin_routes(lines, url))
                result.findings.extend(check_debug_routes(lines, url))
                result.findings.extend(check_api_docs(lines, final_url, url))  # type: ignore[arg-type]

                # Enqueue links for next depth
                if depth < MAX_DEPTH:
                    for href in _LINK_RE.findall(body):
                        candidate = _normalise_url(final_url, href)
                        if candidate and candidate not in visited and _same_origin(start_url, candidate):
                            queue.append((candidate, depth + 1))

        except urllib.error.HTTPError as exc:
            result.errors.append(f"HTTP {exc.code} for {url}")
            result.scanned_urls += 1
        except urllib.error.URLError as exc:
            result.errors.append(f"URL error for {url}: {exc.reason}")
        except Exception as exc:
            result.errors.append(f"Unexpected error for {url}: {exc}")

    return result
