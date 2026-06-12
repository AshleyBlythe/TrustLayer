"""Tests for trustlayer repo scanning heuristics."""

import tempfile
import unittest
from pathlib import Path

from trustlayer.checks import (
    check_admin_routes,
    check_committed_env,
    check_cors,
    check_supabase,
)
from trustlayer.repo_scanner import scan_repo


class TestAdminRouteHeuristics(unittest.TestCase):
    def test_flags_admin_route_without_auth(self):
        lines = [
            'app.get("/admin/users", (req, res) => {',
            "  res.json(users);",
            "});",
        ]
        findings = check_admin_routes(lines, "routes.js")
        self.assertTrue(any(f.check_id == "REPO-020" for f in findings))

    def test_does_not_flag_admin_with_auth_hint(self):
        lines = [
            "requireAuth,",
            'app.get("/admin/users", requireAuth, (req, res) => {',
            "  res.json(users);",
            "});",
        ]
        findings = check_admin_routes(lines, "routes.js")
        self.assertFalse(any(f.check_id == "REPO-020" for f in findings))

    def test_flags_dashboard_route(self):
        lines = ['router.get("/dashboard/settings", handler);']
        findings = check_admin_routes(lines, "app.py")
        self.assertTrue(any(f.check_id == "REPO-020" for f in findings))

    def test_does_not_flag_non_admin_route(self):
        lines = ['app.get("/api/products", handler);']
        findings = check_admin_routes(lines, "routes.js")
        self.assertFalse(findings)


class TestCorsDetection(unittest.TestCase):
    def test_wildcard_cors_header(self):
        lines = ['res.setHeader("Access-Control-Allow-Origin", "*");']
        findings = check_cors(lines, "server.js")
        self.assertTrue(any(f.check_id == "REPO-050" for f in findings))

    def test_cors_origin_star(self):
        lines = ["cors({ origin: '*' })"]
        findings = check_cors(lines, "app.js")
        self.assertTrue(any(f.check_id == "REPO-050" for f in findings))

    def test_django_cors_all(self):
        lines = ["CORS_ORIGIN_ALLOW_ALL = True"]
        findings = check_cors(lines, "settings.py")
        self.assertTrue(any(f.check_id == "REPO-050" for f in findings))

    def test_restricted_cors_not_flagged(self):
        lines = ['Access-Control-Allow-Origin: https://example.com']
        findings = check_cors(lines, "nginx.conf")
        self.assertFalse(findings)


class TestSupabasePatterns(unittest.TestCase):
    def test_wildcard_select_flagged(self):
        lines = [
            "const { data } = await supabase",
            "  .from('messages')",
            "  .select('*')",
        ]
        findings = check_supabase(lines, "api.js")
        self.assertTrue(any(f.check_id == "REPO-090" for f in findings))

    def test_anon_key_flagged(self):
        lines = ["const client = createClient(url, anon key)"]
        findings = check_supabase(lines, "client.js")
        self.assertTrue(any(f.check_id == "REPO-090" for f in findings))

    def test_non_supabase_not_flagged(self):
        lines = ["const data = await db.query('SELECT * FROM items')"]
        findings = check_supabase(lines, "db.js")
        self.assertFalse(findings)


class TestCommittedEnvFile(unittest.TestCase):
    def test_dotenv_flagged(self):
        findings = check_committed_env(Path(".env"), ".env")
        self.assertTrue(any(f.check_id == "REPO-010" for f in findings))

    def test_dotenv_local_flagged(self):
        findings = check_committed_env(Path(".env.local"), ".env.local")
        self.assertTrue(any(f.check_id == "REPO-010" for f in findings))

    def test_dotenv_production_flagged(self):
        findings = check_committed_env(Path(".env.production"), ".env.production")
        self.assertTrue(any(f.check_id == "REPO-010" for f in findings))

    def test_normal_file_not_flagged(self):
        findings = check_committed_env(Path("app.py"), "app.py")
        self.assertFalse(findings)


class TestIgnoredDirectoriesAndBinary(unittest.TestCase):
    def test_node_modules_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir) / "node_modules" / "some-package"
            nm.mkdir(parents=True)
            (nm / "index.js").write_text('API_KEY = "sk-abcdef1234567890abcdef"')
            result = scan_repo(tmpdir)
            sources = [f.source for f in result.findings]
            self.assertFalse(any("node_modules" in s for s in sources))

    def test_binary_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
            result = scan_repo(tmpdir)
            self.assertGreaterEqual(result.skipped_files, 1)

    def test_git_dir_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git" / "config"
            git_dir.parent.mkdir()
            git_dir.write_text('[core]\n\trepositoryformatversion = 0\n')
            result = scan_repo(tmpdir)
            sources = [f.source for f in result.findings]
            self.assertFalse(any(".git" in s for s in sources))


if __name__ == "__main__":
    unittest.main()
