import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as auth_app  # noqa: E402

HTTPS = "https://localhost"
GOOD = {"email": "alice@example.com", "password": "CorrectHorse123"}


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.app = auth_app.create_app({"DATABASE": self.tmp.name, "TESTING": True, "SECRET_KEY": "test-key"})
        self.client = self.app.test_client()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def post(self, path, json=None, client=None):
        return (client or self.client).post(path, json=json, base_url=HTTPS)

    def register_and_login(self):
        self.post("/register", GOOD)
        return self.post("/login", GOOD)

    # ---- 1. Password hashing + input validation ----
    def test_password_is_hashed_not_stored_in_plaintext(self):
        self.post("/register", GOOD)
        import sqlite3
        stored = sqlite3.connect(self.tmp.name).execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn(GOOD["password"], stored)
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_same_password_gets_different_hashes_salted(self):
        self.post("/register", GOOD)
        self.post("/register", {"email": "bob@example.com", "password": GOOD["password"]})
        import sqlite3
        hashes = [r[0] for r in sqlite3.connect(self.tmp.name).execute("SELECT password_hash FROM users")]
        self.assertEqual(len(set(hashes)), 2)

    def test_rejects_invalid_email(self):
        r = self.post("/register", {"email": "not-an-email", "password": GOOD["password"]})
        self.assertEqual(r.status_code, 400)

    def test_rejects_short_password(self):
        r = self.post("/register", {"email": "a@example.com", "password": "short1"})
        self.assertEqual(r.status_code, 400)

    def test_rejects_password_without_numbers(self):
        r = self.post("/register", {"email": "a@example.com", "password": "onlyletterspassword"})
        self.assertEqual(r.status_code, 400)

    def test_rejects_wrong_types_and_missing_body(self):
        self.assertEqual(self.post("/register", {"email": 123, "password": ["x"]}).status_code, 400)
        self.assertEqual(self.client.post("/register", data="not json", base_url=HTTPS).status_code, 400)

    def test_rejects_oversized_password(self):
        r = self.post("/register", {"email": "a@example.com", "password": "a1" * 100})
        self.assertEqual(r.status_code, 400)

    def test_sql_injection_attempt_does_not_log_in(self):
        self.post("/register", GOOD)
        r = self.post("/login", {"email": "' OR '1'='1", "password": "' OR '1'='1"})
        self.assertEqual(r.status_code, 401)

    # ---- 2. Secure cookies, logout, session expiry ----
    def test_session_cookie_has_secure_flags(self):
        r = self.register_and_login()
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Secure", cookie)
        self.assertIn("SameSite=Lax", cookie)

    def test_profile_requires_login(self):
        self.assertEqual(self.client.get("/profile", base_url=HTTPS).status_code, 401)

    def test_login_then_profile_works(self):
        self.register_and_login()
        r = self.client.get("/profile", base_url=HTTPS)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["email"], GOOD["email"])

    def test_logout_ends_session(self):
        self.register_and_login()
        self.assertEqual(self.post("/logout").status_code, 200)
        self.assertEqual(self.client.get("/profile", base_url=HTTPS).status_code, 401)

    def test_session_expires_after_lifetime(self):
        start = 1_000_000.0
        with mock.patch.object(auth_app, "now", return_value=start):
            self.register_and_login()
            self.assertEqual(self.client.get("/profile", base_url=HTTPS).status_code, 200)
        with mock.patch.object(auth_app, "now", return_value=start + auth_app.SESSION_LIFETIME_SECONDS + 1):
            r = self.client.get("/profile", base_url=HTTPS)
            self.assertEqual(r.status_code, 401)

    # ---- 3. Rate limits + generic errors ----
    def test_generic_error_same_for_unknown_user_and_wrong_password(self):
        self.post("/register", GOOD)
        wrong_pw = self.post("/login", {"email": GOOD["email"], "password": "WrongPassword999"})
        unknown = self.post("/login", {"email": "nobody@example.com", "password": "WrongPassword999"})
        self.assertEqual(wrong_pw.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(wrong_pw.get_json(), unknown.get_json())

    def test_duplicate_registration_does_not_reveal_existing_email(self):
        self.post("/register", GOOD)
        dup = self.post("/register", GOOD)
        self.assertEqual(dup.status_code, 400)
        self.assertEqual(dup.get_json()["error"], auth_app.GENERIC_REGISTER_ERROR)

    def test_rate_limit_blocks_after_five_failures(self):
        self.post("/register", GOOD)
        bad = {"email": GOOD["email"], "password": "WrongPassword999"}
        for _ in range(auth_app.MAX_FAILED_ATTEMPTS):
            self.assertEqual(self.post("/login", bad).status_code, 401)
        self.assertEqual(self.post("/login", bad).status_code, 429)
        # even the correct password is blocked while rate limited
        self.assertEqual(self.post("/login", GOOD).status_code, 429)

    def test_rate_limit_resets_after_window(self):
        self.post("/register", GOOD)
        bad = {"email": GOOD["email"], "password": "WrongPassword999"}
        start = 2_000_000.0
        with mock.patch.object(auth_app, "now", return_value=start):
            for _ in range(auth_app.MAX_FAILED_ATTEMPTS):
                self.post("/login", bad)
            self.assertEqual(self.post("/login", bad).status_code, 429)
        with mock.patch.object(auth_app, "now", return_value=start + auth_app.RATE_WINDOW_SECONDS + 1):
            self.assertEqual(self.post("/login", GOOD).status_code, 200)

    def test_responses_are_not_cacheable(self):
        r = self.post("/login", GOOD)
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")


if __name__ == "__main__":
    unittest.main(verbosity=2)
