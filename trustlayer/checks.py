"""Heuristic check functions for TrustLayer repo scanning.

Each check receives file content (as lines) and metadata, and returns a list
of Finding objects.  Checks are intentionally conservative: they flag
*possible* issues for human review rather than asserting certainty.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

from .models import Confidence, Finding, Severity
from .redaction import redact, redact_lines

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    check_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    explanation: str,
    who: str,
    what: str,
    damage: str,
    likelihood: str,
    fix: str,
    ask_human: bool,
    evidence: str,
    source: str,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity,
        confidence=confidence,
        explanation=explanation,
        who_could_use=who,
        what_they_access=what,
        possible_damage=damage,
        likelihood=likelihood,
        fastest_fix=fix,
        ask_human=ask_human,
        evidence=redact(evidence),
        source=source,
    )


# ---------------------------------------------------------------------------
# Secret / credential checks
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "REPO-001",
        "Suspected secret or credential",
        re.compile(
            r'(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token'
            r'|private[_-]?key|client[_-]?secret|password|passwd|db[_-]?pass(?:word)?'
            r'|jwt[_-]?secret|encryption[_-]?key|signing[_-]?key|webhook[_-]?secret'
            r'|stripe[_-]?(?:secret|key)|openai[_-]?(?:api[_-]?)?key'
            r'|anthropic[_-]?(?:api[_-]?)?key|sendgrid[_-]?(?:api[_-]?)?key'
            r'|twilio[_-]?(?:auth[_-]?)?token|aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key'
            r'|github[_-]?token|npm[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9+/=_\-\.]{8,}'
        ),
    ),
    (
        "REPO-002",
        "Possible OpenAI / Anthropic / Stripe style key (sk-...)",
        re.compile(r'\bsk-[A-Za-z0-9\-_]{20,}\b'),
    ),
    (
        "REPO-003",
        "Possible GitHub personal access token",
        re.compile(r'\b(?:ghp|ghs|gho|github_pat)_[A-Za-z0-9_]{10,}\b'),
    ),
    (
        "REPO-004",
        "Possible database URL with embedded credentials",
        re.compile(
            r'(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)'
            r'://[^:/@\s]+:[^\s@"\'`]{4,}@'
        ),
    ),
    (
        "REPO-005",
        "Possible 40-character hex token (git-style)",
        re.compile(r'(?<![a-f0-9])[0-9a-f]{40}(?![a-f0-9])'),
    ),
]


def check_secrets(lines: list[str], source: str) -> List[Finding]:
    findings: List[Finding] = []
    for check_id, title, pattern in _SECRET_PATTERNS:
        hits = [line for line in lines if pattern.search(line)]
        if hits:
            findings.append(_finding(
                check_id=check_id,
                title=title,
                severity=Severity.HIGH,
                confidence=Confidence.POSSIBLE,
                explanation=(
                    "A line matching a common secret or credential pattern was found. "
                    "If this is a real credential it should be rotated immediately and "
                    "moved to a secrets manager or environment variable."
                ),
                who="Anyone with read access to this file or its git history",
                what="Potentially valid credentials or API keys",
                damage="Unauthorized API usage, data access, or account takeover",
                likelihood="High if credential is active and file is public",
                fix="Rotate the credential, add to .gitignore, use environment variables",
                ask_human=True,
                evidence=redact_lines(hits),
                source=source,
            ))
    return findings


# ---------------------------------------------------------------------------
# .env file check
# ---------------------------------------------------------------------------

def check_committed_env(path: Path, source: str) -> List[Finding]:
    name = path.name.lower()
    if name == ".env" or re.match(r"^\.env\.", name):
        return [_finding(
            check_id="REPO-010",
            title="Committed .env file",
            severity=Severity.HIGH,
            confidence=Confidence.OBSERVED,
            explanation=(
                ".env files often contain secrets, API keys, and database passwords. "
                "Committing them exposes those values to anyone who can read the repo."
            ),
            who="Anyone with repo read access",
            what="All environment variables in the file",
            damage="Full credential exposure",
            likelihood="High if repo is public or broadly shared",
            fix="Add .env to .gitignore, remove from git history, rotate any secrets",
            ask_human=True,
            evidence=f"File present: {source}",
            source=source,
        )]
    return []


# ---------------------------------------------------------------------------
# Unsafe public env var patterns (client-side frameworks)
# ---------------------------------------------------------------------------

_PUBLIC_ENV_PATTERN = re.compile(
    r'(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_)'
    r'(?:secret|key|token|password|api[_-]?key|private)'
)


def check_public_env_vars(lines: list[str], source: str) -> List[Finding]:
    hits = [l for l in lines if _PUBLIC_ENV_PATTERN.search(l)]
    if not hits:
        return []
    return [_finding(
        check_id="REPO-011",
        title="Sensitive value in a public environment variable",
        severity=Severity.HIGH,
        confidence=Confidence.POSSIBLE,
        explanation=(
            "Variables prefixed NEXT_PUBLIC_, VITE_, REACT_APP_, etc. are bundled "
            "into the client-side JavaScript and visible to all users. "
            "Secrets in these variables are fully public."
        ),
        who="Any visitor to the deployed site",
        what="The variable value embedded in the JS bundle",
        damage="Key/token exposed to all end-users and scrapers",
        likelihood="Certain if deployed",
        fix="Move to a server-side-only variable; use a backend proxy for API calls",
        ask_human=True,
        evidence=redact_lines(hits),
        source=source,
    )]


# ---------------------------------------------------------------------------
# Admin routes without obvious auth hints
# ---------------------------------------------------------------------------

_ADMIN_ROUTE = re.compile(
    r'(?i)(?:route|path|endpoint|app\.(?:get|post|put|delete|use)|router\.(?:get|post|put|delete|use))'
    r'[^"\'\n]*["\'][^"\']*(?:/admin|/dashboard|/management|/superuser|/staff|/internal)[^"\']*["\']'
)
_AUTH_HINT = re.compile(
    r'(?i)(?:auth|middleware|require_login|login_required|protect|guard|authenticate|authorize|jwt|session)'
)


def check_admin_routes(lines: list[str], source: str) -> List[Finding]:
    hits = []
    for i, line in enumerate(lines):
        if _ADMIN_ROUTE.search(line):
            context_block = lines[max(0, i - 3): i + 4]
            if not any(_AUTH_HINT.search(cl) for cl in context_block):
                hits.append(line)
    if not hits:
        return []
    return [_finding(
        check_id="REPO-020",
        title="Admin route without obvious auth hint nearby",
        severity=Severity.MEDIUM,
        confidence=Confidence.NEEDS_VERIFICATION,
        explanation=(
            "A route matching admin/dashboard/management patterns was found without "
            "an obvious authentication or authorization call in the surrounding lines. "
            "This may be protected elsewhere, but deserves manual review."
        ),
        who="Any user who discovers the URL",
        what="Admin interface or sensitive management functions",
        damage="Privilege escalation, data modification, account takeover",
        likelihood="Medium — depends on whether auth is applied at middleware level",
        fix="Verify auth middleware is applied; add explicit route-level auth guard",
        ask_human=True,
        evidence=redact_lines(hits),
        source=source,
    )]


# ---------------------------------------------------------------------------
# Debug / test / demo / playground routes
# ---------------------------------------------------------------------------

_DEBUG_ROUTE = re.compile(
    r'(?i)["\'][^"\']*(?:/debug|/test|/demo|/playground|/dev|/__debug|/health-internal'
    r'|/metrics-internal|/trace)[^"\']*["\']'
)


def check_debug_routes(lines: list[str], source: str) -> List[Finding]:
    hits = [l for l in lines if _DEBUG_ROUTE.search(l)]
    if not hits:
        return []
    return [_finding(
        check_id="REPO-021",
        title="Debug, test, or demo route",
        severity=Severity.LOW,
        confidence=Confidence.POSSIBLE,
        explanation=(
            "Routes named debug, test, demo, or playground are sometimes left active "
            "in production and may expose internal state or bypass normal restrictions."
        ),
        who="Curious users, automated scanners",
        what="Internal diagnostics, test data, or unauthenticated functionality",
        damage="Information disclosure, unexpected feature exposure",
        likelihood="Low to medium",
        fix="Remove or gate behind environment check before deploying to production",
        ask_human=False,
        evidence=redact_lines(hits),
        source=source,
    )]


# ---------------------------------------------------------------------------
# Source maps and build artifacts
# ---------------------------------------------------------------------------

_SOURCEMAP_PATTERN = re.compile(r'\.map$', re.IGNORECASE)
_SOURCEMAP_REFERENCE = re.compile(r'//[#@]\s*sourceMappingURL\s*=\s*\S+\.map')


def check_source_maps(path: Path, lines: list[str], source: str) -> List[Finding]:
    findings: List[Finding] = []
    if _SOURCEMAP_PATTERN.search(path.name):
        findings.append(_finding(
            check_id="REPO-030",
            title="Source map file present in repository",
            severity=Severity.LOW,
            confidence=Confidence.OBSERVED,
            explanation=(
                "Source map files reverse-engineer minified JS/CSS back to readable "
                "source code. Deploying them publicly exposes your application logic."
            ),
            who="Developers, security researchers, attackers",
            what="Original source code structure and logic",
            damage="Intellectual property exposure, easier vulnerability discovery",
            likelihood="Certain if deployed alongside the JS bundle",
            fix="Exclude *.map files from public deployment; add to .gitignore if generated",
            ask_human=False,
            evidence=f"File: {source}",
            source=source,
        ))
    hits = [l for l in lines if _SOURCEMAP_REFERENCE.search(l)]
    if hits:
        findings.append(_finding(
            check_id="REPO-031",
            title="Source map reference in JavaScript bundle",
            severity=Severity.LOW,
            confidence=Confidence.OBSERVED,
            explanation="This file references a .map file that may be publicly accessible.",
            who="Anyone viewing the deployed site",
            what="Source map and reconstructed source code",
            damage="Source code exposure",
            likelihood="Depends on whether .map file is deployed",
            fix="Configure your bundler to omit sourceMappingURL in production builds",
            ask_human=False,
            evidence=redact_lines(hits),
            source=source,
        ))
    return findings


# ---------------------------------------------------------------------------
# Sensitive files under public / static directories
# ---------------------------------------------------------------------------

_SENSITIVE_FILENAMES = re.compile(
    r'(?i)(?:\.env|\.pem|\.key|\.p12|\.pfx|id_rsa|id_ed25519|credentials'
    r'|secrets|config\.json|settings\.json|database\.yml|database\.yaml'
    r'|firebase\.json|service[_-]?account\.json)$'
)


def check_sensitive_in_public(path: Path, source: str) -> List[Finding]:
    parts = [p.lower() for p in path.parts]
    in_public = any(p in ("public", "static", "assets", "dist", "out", "build") for p in parts)
    if in_public and _SENSITIVE_FILENAMES.search(path.name):
        return [_finding(
            check_id="REPO-040",
            title="Sensitive file under a public/static directory",
            severity=Severity.HIGH,
            confidence=Confidence.OBSERVED,
            explanation=(
                f"{path.name!r} appears under a directory that is likely served "
                "publicly. This may expose secrets or configuration to the internet."
            ),
            who="Any internet user",
            what="File contents, potentially including secrets or certificates",
            damage="Full credential or private key exposure",
            likelihood="High if the directory is web-served",
            fix="Move sensitive files outside the web root; never commit secrets",
            ask_human=True,
            evidence=f"File path: {source}",
            source=source,
        )]
    return []


# ---------------------------------------------------------------------------
# Permissive CORS patterns
# ---------------------------------------------------------------------------

_CORS_WILDCARD = re.compile(
    r'(?i)(?:Access-Control-Allow-Origin["\']?\s*[=:,]\s*["\']?\*'
    r'|cors\s*\(\s*\{[^}]*origin\s*:\s*["\']?\*'
    r'|allow_origins\s*=\s*\[["\']?\*'
    r'|CORS_ORIGIN_ALLOW_ALL\s*=\s*True)'
)


def check_cors(lines: list[str], source: str) -> List[Finding]:
    hits = [l for l in lines if _CORS_WILDCARD.search(l)]
    if not hits:
        return []
    return [_finding(
        check_id="REPO-050",
        title="Permissive CORS policy (wildcard origin)",
        severity=Severity.MEDIUM,
        confidence=Confidence.OBSERVED,
        explanation=(
            "Access-Control-Allow-Origin: * allows any website to make "
            "cross-origin requests to this server. Combined with cookies or "
            "other credentials this can enable CSRF-style attacks."
        ),
        who="Any website the user visits",
        what="Data returned by credentialed cross-origin requests",
        damage="Data theft via cross-origin requests from malicious sites",
        likelihood="Medium — depends on whether credentials are also allowed",
        fix="Restrict CORS to known origins; never combine wildcard with credentials",
        ask_human=True,
        evidence=redact_lines(hits),
        source=source,
    )]


# ---------------------------------------------------------------------------
# Sensitive logs, exports, dumps
# ---------------------------------------------------------------------------

_DUMP_PATTERN = re.compile(
    r'(?i)(?:\.sql$|\.dump$|chat[_-]?history|user[_-]?export|user[_-]?data'
    r'|database[_-]?backup|db[_-]?backup|logs?/.*\.log$|debug\.log$|error\.log$'
    r'|access\.log$)'
)


def check_sensitive_files(path: Path, source: str) -> List[Finding]:
    if _DUMP_PATTERN.search(str(path)):
        return [_finding(
            check_id="REPO-060",
            title="Possible sensitive data file (log, export, or dump)",
            severity=Severity.MEDIUM,
            confidence=Confidence.POSSIBLE,
            explanation=(
                f"{path.name!r} matches patterns for database dumps, chat histories, "
                "user exports, or application logs, which may contain PII or sensitive data."
            ),
            who="Anyone with repo or deploy access",
            what="User data, PII, query results, or internal logs",
            damage="Privacy violation, regulatory risk (GDPR/CCPA), data breach",
            likelihood="Medium",
            fix="Add to .gitignore; delete from repo history; never commit user data",
            ask_human=True,
            evidence=f"File: {source}",
            source=source,
        )]
    return []


# ---------------------------------------------------------------------------
# Demo / test credentials in code
# ---------------------------------------------------------------------------

_DEMO_CRED = re.compile(
    r'(?i)(?:password|passwd|secret)\s*[=:]\s*["\'](?:password|test|demo|admin'
    r'|123456|changeme|secret|letmein|qwerty|abc123|pass)["\']'
)


def check_demo_credentials(lines: list[str], source: str) -> List[Finding]:
    hits = [l for l in lines if _DEMO_CRED.search(l)]
    if not hits:
        return []
    return [_finding(
        check_id="REPO-070",
        title="Demo or test credential in source code",
        severity=Severity.MEDIUM,
        confidence=Confidence.POSSIBLE,
        explanation=(
            "A common demo/test password was found hard-coded. If this is used "
            "in a real account or seeded to production it can be trivially guessed."
        ),
        who="Anyone who reads the source",
        what="The account or system the credential belongs to",
        damage="Unauthorized access to accounts seeded with these credentials",
        likelihood="Medium if seeded to prod database",
        fix="Use randomly generated credentials for all environments; never hard-code",
        ask_human=False,
        evidence=redact_lines(hits),
        source=source,
    )]


# ---------------------------------------------------------------------------
# OpenAPI / Swagger / GraphQL / API docs
# ---------------------------------------------------------------------------

_API_DOC_PATTERN = re.compile(
    r'(?i)(?:swagger|openapi|graphql|graphiql|api[_-]?docs?|redoc|stoplight)'
)
_API_DOC_ROUTE = re.compile(
    r'(?i)["\'][^"\']*(?:/swagger|/openapi|/graphql|/graphiql|/api-docs?|/redoc)[^"\']*["\']'
)


def check_api_docs(lines: list[str], path: Path, source: str) -> List[Finding]:
    hits: list[str] = []
    if _API_DOC_PATTERN.search(path.name):
        hits.append(f"File: {source}")
    hits += [l for l in lines if _API_DOC_ROUTE.search(l)]
    if not hits:
        return []
    return [_finding(
        check_id="REPO-080",
        title="API documentation endpoint or file",
        severity=Severity.INFO,
        confidence=Confidence.POSSIBLE,
        explanation=(
            "API documentation (Swagger, OpenAPI, GraphQL explorer) exposed publicly "
            "reveals your API surface to potential attackers and aids enumeration."
        ),
        who="Security researchers, attackers",
        what="Full API schema, endpoints, and parameter names",
        damage="Easier targeted attacks, credential stuffing against discovered endpoints",
        likelihood="Low direct risk; raises overall attack surface",
        fix="Gate API docs behind authentication in production; disable GraphiQL in prod",
        ask_human=False,
        evidence=redact_lines(hits),
        source=source,
    )]


# ---------------------------------------------------------------------------
# Supabase RLS / storage risk clues
# ---------------------------------------------------------------------------

_SUPABASE_RLS = re.compile(
    r'(?i)(?:\.from\s*\(["\'][^"\']+["\']\)\s*\.select\b'
    r'|supabase\.storage\.from'
    r'|createClient\s*\([^)]*supabase'
    r'|SUPABASE_(?:URL|KEY|ANON|SERVICE)'
    r'|anon[_\s]key'
    r'|\bsupabase\b)',
)
_RLS_CONCERN = re.compile(r'(?i)(?:\.select\(\s*["\']?\*\s*["\']?\)|anon[\s_]key|service_role)')


def check_supabase(lines: list[str], source: str) -> List[Finding]:
    has_supabase = any(_SUPABASE_RLS.search(l) for l in lines)
    if not has_supabase:
        return []
    rls_concern_lines = [l for l in lines if _RLS_CONCERN.search(l)]
    if not rls_concern_lines:
        return []
    return [_finding(
        check_id="REPO-090",
        title="Supabase query pattern — RLS or storage policy review needed",
        severity=Severity.MEDIUM,
        confidence=Confidence.NEEDS_VERIFICATION,
        explanation=(
            "Supabase queries using wildcard selects or the anon/service_role key "
            "may expose data if Row Level Security (RLS) policies are missing or "
            "misconfigured. Storage bucket policies also need explicit review."
        ),
        who="Any authenticated or anonymous user of the app",
        what="Database rows or storage objects that RLS should protect",
        damage="Data leakage across user accounts",
        likelihood="Depends on RLS policy configuration",
        fix="Enable RLS on all tables; audit anon-key policies; review storage bucket ACLs",
        ask_human=True,
        evidence=redact_lines(rls_concern_lines),
        source=source,
    )]


# ---------------------------------------------------------------------------
# Package manifests — flag for dependency audit follow-up
# ---------------------------------------------------------------------------

_MANIFEST_NAMES = {"package.json", "requirements.txt", "Pipfile", "pyproject.toml",
                   "Gemfile", "go.mod", "Cargo.toml", "composer.json", "pom.xml",
                   "build.gradle", "package-lock.json", "yarn.lock", "poetry.lock",
                   "Pipfile.lock", "Cargo.lock"}


def check_manifest(path: Path, source: str) -> List[Finding]:
    if path.name in _MANIFEST_NAMES:
        return [_finding(
            check_id="REPO-100",
            title="Package manifest or lockfile — dependency audit recommended",
            severity=Severity.INFO,
            confidence=Confidence.OBSERVED,
            explanation=(
                f"{path.name!r} lists project dependencies. TrustLayer does not audit "
                "dependencies for known CVEs (that requires a dedicated tool). "
                "Consider running `pip-audit`, `npm audit`, or `osv-scanner`."
            ),
            who="N/A — informational only",
            what="N/A",
            damage="Unpatched vulnerabilities in dependencies",
            likelihood="Varies by ecosystem and package versions",
            fix="Run a dependency audit tool before launch and on a regular schedule",
            ask_human=False,
            evidence=f"File: {source}",
            source=source,
        )]
    return []
