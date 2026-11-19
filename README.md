# Secure Authentication Demo

EdVyro Cyber Security Virtual Internship - Milestone 3: defensive authentication controls demonstrated with automated tests.

Author: ALTAHER MOHAMMED ELTAHER

## What it implements

| Requirement | Implementation |
|---|---|
| Password hashing | Salted scrypt hashes via Werkzeug (`generate_password_hash`); plaintext is never stored |
| Server-side input validation | Email format, password length (10-128) and complexity, type checks, request size limit |
| Secure cookies | `HttpOnly`, `Secure`, `SameSite=Lax` |
| Logout | `POST /logout` clears the session |
| Session expiry | 15 minutes, enforced on the server (not only by the cookie) |
| Rate limiting | 5 failed logins per email + IP in 5 minutes, then HTTP 429 |
| Generic errors | Same message for unknown email and wrong password; duplicate registration reveals nothing |

## Run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py            # development only
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```

The saved result of a run is in `test_output.txt` (18 tests, all passing).

## Endpoints

- `POST /register` with JSON `{"email": "...", "password": "..."}`
- `POST /login` with the same JSON
- `POST /logout`
- `GET /profile` (requires login)

See `SECURITY_NOTE.md` for the security explanation.

## Repository safety

No secrets are committed. `SECRET_KEY` comes from the environment.
