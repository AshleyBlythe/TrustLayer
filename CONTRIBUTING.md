# Contributing to TrustLayer

Thanks for your interest! TrustLayer is a community build-literacy tool — contributions
of all kinds are welcome.

## Ways to contribute

- **Add or improve heuristic checks** in `trustlayer/checks.py`
- **Write tests** for edge cases or new check patterns
- **Improve plain-English explanations** in finding descriptions
- **Documentation** — docs/CHECKS.md, README, etc.
- **Bug reports** via GitHub Issues

## Ground rules

1. **No new required dependencies.** TrustLayer must stay dependency-free (stdlib only).
2. **Checks must be conservative.** False positives annoy users; when in doubt, use `Confidence.NEEDS_VERIFICATION`.
3. **Evidence in reports must go through redaction.** Never output raw secrets, even in tests.
4. **Do not add language claiming full security coverage.**
5. Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

```bash
git clone https://github.com/AshleyBlythe/TrustLayer
cd TrustLayer
python -m unittest discover tests/
```

No virtual environment is required for development (no dependencies), but one is
still a good practice for isolation.

## Adding a new check

1. Add your check function to `trustlayer/checks.py` following the existing pattern.
2. Assign a stable `check_id` (e.g. `REPO-110` for repo checks, `URL-020` for URL checks).
3. Call it from `repo_scanner.py` or `url_scanner.py` as appropriate.
4. Add tests in `tests/`.
5. Document the check in `docs/CHECKS.md`.

## Pull requests

- Keep PRs focused — one check or fix per PR.
- Include tests for new behaviour.
- Update `CHANGELOG.md` with a brief entry.
- PRs are reviewed by maintainers; expect feedback within a few days.
