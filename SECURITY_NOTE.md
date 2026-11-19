# Authentication Security Note

## Goal
Show that a small login system can resist common authentication attacks, and prove it with automated tests.

## Controls and why they matter

1. **Password hashing (scrypt, salted).** If the database leaks, attackers get slow, salted hashes instead of passwords. Identical passwords produce different hashes, so one cracked hash does not expose others.
2. **Server-side input validation.** The browser can be bypassed, so the server checks email format, types, password length and complexity, and body size. Parameterized SQL queries prevent SQL injection.
3. **Secure cookie settings.** `HttpOnly` blocks JavaScript from reading the session (limits XSS theft), `Secure` sends it only over HTTPS, and `SameSite=Lax` reduces CSRF risk.
4. **Logout and session expiry.** Logout clears the session. Sessions also expire after 15 minutes and this is checked on the server, so an old cookie cannot be reused. The session is reset at login to prevent session fixation.
5. **Rate limiting.** After 5 failed attempts for the same email and IP within 5 minutes, further logins get HTTP 429, which slows brute force and credential stuffing.
6. **Generic errors.** Unknown email and wrong password give the same response, and a dummy hash check keeps timing similar, so attackers cannot discover which emails are registered. Duplicate registration also returns a generic message.

## Known limitations (next steps)
- The rate limiter is in memory; production needs a shared store such as Redis.
- Add multi-factor authentication, CSRF tokens for form-based pages, and account lockout notifications.
- Run behind HTTPS with a production WSGI server and a managed secret key.

## Evidence
`test_output.txt` shows 18 automated tests covering every control above.
