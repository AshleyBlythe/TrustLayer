# TrustLayer

**Build-literacy and launch-readiness assistant for non-security builders, vibe coders, and AI-built apps.**

TrustLayer scans a local repo — and optionally a deployed preview URL — for common data exposure, privacy, and build-readiness risks, then explains findings in plain English.

> ⚠️ **TrustLayer is not a professional security audit.** It uses lightweight heuristics and may produce false positives. No automated scan can replace human review before launch.

---

## Quick start

```bash
# Scan a local repo and write reports
python -m trustlayer scan . --report trustlayer-report.md --json trustlayer-report.json

# Include a URL crawl of your preview deployment
python -m trustlayer scan . --url https://preview.example.com \
  --report trustlayer-report.md --json trustlayer-report.json
```

No dependencies beyond Python 3.10+.

---

## What it checks

### Repo checks
- Suspected secrets and credentials (best-effort redaction in reports)
- Committed `.env` files
- Unsafe public environment variable patterns (`NEXT_PUBLIC_`, `VITE_`, etc.)
- Admin routes without obvious auth hints nearby
- Debug / test / demo / playground routes
- Source maps and source map references in JS bundles
- Sensitive files under `public/` or `static/` directories
- Permissive CORS patterns (wildcard origins)
- Sensitive files: logs, chat histories, user exports, database dumps
- Demo / test credentials hard-coded in source
- OpenAPI / Swagger / GraphQL / API documentation endpoints
- Supabase RLS and storage policy risk clues
- Package manifests and lockfiles (flags for dependency-audit follow-up)

### URL crawl (opt-in, `--url`)
- GET-only, same-origin, bounded depth (max 3) and page count (max 50)
- Cross-origin redirect detection
- CORS headers
- Server / X-Powered-By version disclosure
- Inline secret patterns in page content
- Admin and debug routes in HTML

See [docs/CHECKS.md](docs/CHECKS.md) for the full check reference.

---

## Report format

Every report includes:

- **Report-sharing warning** — reminding you to review before distributing
- **Automated findings score** — severity counts, never "100/100 ready to launch"
- **Coverage and limitations** — what TrustLayer can and cannot do
- Per-finding: title, severity, confidence, plain-English explanation, who could exploit it, what they'd access, possible damage, likelihood, fastest fix, ask-a-human flag, sanitised evidence, source file/URL, stable check ID

---

## Safety and limitations

- **Redaction is best-effort, not guaranteed.** Always review reports before sharing.
- **URL scans create real traffic** and will appear in server logs. Only scan systems you own or have permission to test.
- **No hosted scanning API** — TrustLayer is a local CLI tool. Do not expose it as a service without SSRF and abuse protections.
- Findings labelled `needs_verification` are especially uncertain and require manual review.

See [docs/SAFETY.md](docs/SAFETY.md) for the full safety policy.

---

## Development

```bash
# Run tests
python -m pytest tests/
# or with unittest
python -m unittest discover tests/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

A [FLARE](https://github.com/AshleyBlythe/TrustLayer) open-source project.
