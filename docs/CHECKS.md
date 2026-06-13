# TrustLayer Check Reference

All check IDs are stable across versions. Findings include a `check_id` field
you can use to suppress or filter specific checks.

## Repo checks

| Check ID | Title | Severity | Confidence |
|----------|-------|----------|------------|
| REPO-001 | Suspected secret or credential | HIGH | possible |
| REPO-002 | Possible OpenAI / Anthropic / Stripe style key (sk-...) | HIGH | possible |
| REPO-003 | Possible GitHub personal access token | HIGH | possible |
| REPO-004 | Possible database URL with embedded credentials | HIGH | possible |
| REPO-005 | Possible 40-character hex token | HIGH | possible |
| REPO-010 | Committed .env file | HIGH | observed |
| REPO-011 | Sensitive value in a public environment variable | HIGH | possible |
| REPO-020 | Admin route without obvious auth hint nearby | MEDIUM | needs_verification |
| REPO-021 | Debug, test, or demo route | LOW | possible |
| REPO-030 | Source map file present in repository | LOW | observed |
| REPO-031 | Source map reference in JavaScript bundle | LOW | observed |
| REPO-040 | Sensitive file under a public/static directory | HIGH | observed |
| REPO-050 | Permissive CORS policy (wildcard origin) | MEDIUM | observed |
| REPO-060 | Possible sensitive data file (log, export, or dump) | MEDIUM | possible |
| REPO-070 | Demo or test credential in source code | MEDIUM | possible |
| REPO-080 | API documentation endpoint or file | INFO | possible |
| REPO-090 | Supabase query pattern — RLS or storage policy review needed | MEDIUM | needs_verification |
| REPO-100 | Package manifest or lockfile — dependency audit recommended | INFO | observed |

## URL checks

| Check ID | Title | Severity | Confidence |
|----------|-------|----------|------------|
| URL-001 | Cross-origin redirect detected | INFO | observed |
| CORS-001 | Permissive CORS header on URL | MEDIUM | observed |
| URL-010 | Server version disclosure header | INFO | observed |
| URL-011 | X-Powered-By header discloses technology stack | INFO | observed |

URL scans also run the following repo checks against page HTML content:
REPO-001 through REPO-005 (secrets), REPO-050 (CORS), REPO-020 (admin routes),
REPO-021 (debug routes), REPO-080 (API docs).

## Confidence levels

- **observed** — the pattern was directly matched in the file or response
- **possible** — heuristic match; needs human confirmation
- **needs_verification** — context was ambiguous; review manually before acting

## Skipped files and directories

The following are never scanned:
- `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`, `dist`, `.next`, `.nuxt`
- Binary files (images, fonts, archives, compiled objects)
- Files larger than 512 KB
