# TrustLayer Safety Policy

## What TrustLayer is

TrustLayer is a **build-literacy tool** for developers who want a quick sanity
check before launching a project. It uses lightweight pattern matching to flag
common issues for human review.

## What TrustLayer is not

- **Not a professional security audit.** TrustLayer cannot replace a penetration
  test, a security-focused code review, or compliance assessment.
- **Not a guarantee.** Passing a TrustLayer scan does not mean your project is
  secure. It means no obvious patterns were detected by these particular heuristics.
- **Not comprehensive.** TrustLayer does not check authentication logic, business
  rules, runtime behaviour, dependency vulnerabilities, or infrastructure configuration.

## Redaction

TrustLayer applies best-effort redaction before writing evidence to reports.
Redaction uses regex patterns and will catch common secret formats, but:

- Novel or obfuscated secrets may not be caught.
- Partial values may still appear (e.g., a prefix like `sk-` before `[REDACTED]`).
- **Always review reports before sharing**, especially outside your team.

## URL scanning

The `--url` flag enables a bounded crawler:

- **GET requests only** — no form submissions, no mutations, no authentication attempts.
- **Same-origin** — TrustLayer will not follow links to different domains.
- **Bounded** — maximum 50 pages, depth 3, 10-second connection timeout, 1 MB per page.
- **Recognisable** — uses a `TrustLayer-Scanner/0.1` User-Agent so server owners can identify the traffic.
- **Creates real traffic** — scans will appear in access logs. Only scan systems you own or have explicit permission to test.

**Do not expose TrustLayer's URL scanning as a hosted service** without
implementing SSRF protections, rate limiting, and abuse controls.

## False positives

TrustLayer is designed to err on the side of flagging more rather than less.
Many findings will be false positives, especially `needs_verification` confidence
findings. This is intentional — the goal is to prompt human review, not to assert certainty.

## Responsible use

- Only scan repositories and URLs you own or have permission to scan.
- Do not use TrustLayer output as a compliance statement.
- Do not share reports publicly without reviewing them first.
- Use findings as a starting checklist, not a final verdict.
