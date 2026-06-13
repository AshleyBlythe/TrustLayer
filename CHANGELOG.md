# Changelog

All notable changes to TrustLayer will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] — Initial release

### Added
- Dependency-free Python 3.10+ CLI (`python -m trustlayer scan`)
- Repo scanner with checks for:
  - Secrets and credentials (REPO-001 through REPO-005)
  - Committed `.env` files (REPO-010)
  - Unsafe public env var patterns (REPO-011)
  - Admin routes without auth hints (REPO-020)
  - Debug/test/demo routes (REPO-021)
  - Source maps (REPO-030, REPO-031)
  - Sensitive files in public directories (REPO-040)
  - Permissive CORS (REPO-050)
  - Sensitive data files (REPO-060)
  - Demo/test credentials (REPO-070)
  - API documentation exposure (REPO-080)
  - Supabase RLS/storage patterns (REPO-090)
  - Package manifest dependency-audit flag (REPO-100)
- Optional bounded GET-only URL crawler
- Markdown and JSON report writers with best-effort secret redaction
- Report-sharing warning and coverage/limitations section
- GitHub Actions test workflow
- Apache-2.0 license
