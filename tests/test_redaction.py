"""Tests for trustlayer.redaction."""

import unittest
from trustlayer.redaction import redact, redact_lines


class TestRedactQuotedSecrets(unittest.TestCase):
    def test_quoted_secret_with_spaces(self):
        line = 'api_key = "my secret key value here"'
        result = redact(line)
        self.assertNotIn("my secret key value here", result)
        self.assertIn("[REDACTED]", result)

    def test_single_quoted_secret(self):
        line = "password = 'supersecret123'"
        result = redact(line)
        self.assertNotIn("supersecret123", result)

    def test_env_style_assignment(self):
        line = "OPENAI_API_KEY=sk-abc123definitelyreal"
        result = redact(line)
        self.assertNotIn("abc123definitelyreal", result)


class TestRedactJsonYaml(unittest.TestCase):
    def test_json_style_secret(self):
        line = '{"api_key": "xyzSECRETxyz1234567"}'
        result = redact(line)
        self.assertNotIn("xyzSECRETxyz1234567", result)

    def test_yaml_style_secret(self):
        line = "jwt_secret: mysupersecretjwtvalue"
        result = redact(line)
        self.assertNotIn("mysupersecretjwtvalue", result)

    def test_nested_secret(self):
        line = '  "signing_key": "AAABBBCCC12345678"'
        result = redact(line)
        self.assertNotIn("AAABBBCCC12345678", result)


class TestRedactDatabaseUrls(unittest.TestCase):
    def test_postgres_url(self):
        line = "DATABASE_URL=postgres://user:hunter2@localhost:5432/mydb"
        result = redact(line)
        self.assertNotIn("hunter2", result)
        self.assertIn("[REDACTED]", result)
        self.assertIn("localhost", result)

    def test_mysql_url(self):
        line = "DB=mysql://admin:p@ssw0rd@db.example.com/shop"
        result = redact(line)
        self.assertNotIn("p@ssw0rd", result)

    def test_mongodb_url(self):
        line = "MONGO_URI=mongodb://myuser:mypass123@cluster.mongodb.net/db"
        result = redact(line)
        self.assertNotIn("mypass123", result)


class TestRedactAuthHeaders(unittest.TestCase):
    def test_bearer_token(self):
        line = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9XXXX"
        result = redact(line)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9XXXX", result)

    def test_api_key_header(self):
        line = "Authorization: ApiKey ABCDEFGHIJ1234567890"
        result = redact(line)
        self.assertNotIn("ABCDEFGHIJ1234567890", result)

    def test_cookie_session(self):
        line = "Set-Cookie: session_token=abc123secretvalue; HttpOnly"
        result = redact(line)
        self.assertNotIn("abc123secretvalue", result)


class TestRedactUrlCredentials(unittest.TestCase):
    def test_url_with_password(self):
        line = "endpoint = https://admin:mysecret@api.example.com/v1"
        result = redact(line)
        self.assertNotIn("mysecret", result)
        self.assertIn("api.example.com", result)

    def test_api_key_query_param(self):
        line = "https://api.example.com/data?api_key=realKeyValue123&format=json"
        result = redact(line)
        self.assertNotIn("realKeyValue123", result)

    def test_token_query_param(self):
        line = "https://service.io/webhook?token=secr3tT0k3n&event=push"
        result = redact(line)
        self.assertNotIn("secr3tT0k3n", result)

    def test_access_token_query(self):
        line = "https://api.example.com?access_token=MYACCESSTOKEN99"
        result = redact(line)
        self.assertNotIn("MYACCESSTOKEN99", result)


class TestRedactSkLines(unittest.TestCase):
    def test_sk_key(self):
        result = redact("key = sk-realSecretKey12345678901234")
        self.assertNotIn("realSecretKey12345678901234", result)
        self.assertIn("sk-[REDACTED]", result)

    def test_github_token(self):
        result = redact("token = ghp_abcdefghij1234567890")
        self.assertNotIn("ghp_abcdefghij1234567890", result)

    def test_hex40(self):
        result = redact("sha = a" * 0 + "a" * 40)
        self.assertIn("[HEX40-REDACTED]", result)


class TestRedactLines(unittest.TestCase):
    def test_max_lines_cap(self):
        lines = [f"api_key = 'secret{i}abcdefghij'" for i in range(10)]
        result = redact_lines(lines, max_lines=3)
        self.assertIn("more lines omitted", result)
        result_lines = result.split("\n")
        self.assertLessEqual(len(result_lines), 5)

    def test_no_secrets_in_output(self):
        lines = ["api_key = 'supersecret12345'", "normal line"]
        result = redact_lines(lines)
        self.assertNotIn("supersecret12345", result)


class TestReportNeverContainsFixtureSecrets(unittest.TestCase):
    """Ensure that going through the full pipeline, fixture secrets don't leak."""

    def test_full_pipeline_redaction(self):
        import tempfile, os
        from pathlib import Path
        from trustlayer.repo_scanner import scan_repo
        from trustlayer.reporting import write_markdown, write_json

        secret = "FIXTURE_SECRET_XYZ_1234567890abcdef"
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write a file with a known secret pattern
            (Path(tmpdir) / "config.py").write_text(
                f'API_KEY = "{secret}"\n', encoding="utf-8"
            )
            result = scan_repo(tmpdir)

            md_path = Path(tmpdir) / "report.md"
            json_path = Path(tmpdir) / "report.json"
            write_markdown(result, str(md_path))
            write_json(result, str(json_path))

            md_content = md_path.read_text()
            json_content = json_path.read_text()

            self.assertNotIn(secret, md_content)
            self.assertNotIn(secret, json_content)


if __name__ == "__main__":
    unittest.main()
