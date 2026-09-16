# PortSwigger Web Security Academy — SQL Injection (Day 3)

My notes and write-ups from Day 3 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md) and **Authentication** on [Day 2](day2-authentication.md), I moved on to the **SQL Injection** topic and worked through 10 labs (9 Apprentice-level, 1 Practitioner-level).

## What is "SQL injection"?

SQL injection happens when user-controlled input is concatenated directly into a SQL query instead of being passed as a properly separated parameter, letting an attacker change the *structure* of the query itself — not just the data it operates on. Every lab below abuses that same root cause in a different way: bypassing a `WHERE` clause filter, forging a login, fingerprinting the database engine, walking its internal metadata tables to find hidden schema, and — when the application shows no query output at all — inferring data one true/false question or one character at a time. The recurring lesson: **string-building a query from untrusted input is never safe, no matter how the result is eventually used or displayed.**

---

## Lab 1: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data

**Vulnerability:** The product category filter builds a query like `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`, directly concatenating the category value from the URL. Since `released = 1` is just more SQL text tacked on, it can be neutralized like any other part of the query.

**Steps:**
1. Tried commenting out the trailing condition with `category=Gifts'--`, which technically works (a genuinely hidden product appeared) but didn't flip the lab to solved — the app's check apparently wants *all* hidden products surfaced, not just the one belonging to the selected category.
2. Used `category=Gifts' OR 1=1--` instead: the `'` closes the string literal, `OR 1=1` makes the `WHERE` clause always true regardless of category or release status, and `--` comments out the rest of the original query.
3. The response listed every product in the catalog, released and unreleased alike → lab solved.

**Takeaway:** Even a syntactically correct, "working" injection isn't necessarily the intended solution — read what the lab is actually asking the database to reveal. `OR 1=1` is the classic way to make a `WHERE` clause unconditionally true and return everything a table holds.

---

## Lab 2: SQL injection vulnerability allowing login bypass
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/lab-login-bypass

**Vulnerability:** The login form builds a query like `SELECT * FROM users WHERE username = 'x' AND password = 'y'`, concatenating both the username and password fields straight into the SQL text with no parameterization.

**Steps:**
1. Entered `administrator'--` as the username, with any arbitrary value as the password.
2. The `'` closes the username string, and `--` comments out everything after it — including the entire password check.
3. The resulting query effectively became `SELECT * FROM users WHERE username = 'administrator'`, which matches the admin row regardless of what password was submitted.
4. Logged in as `administrator` with no valid password required → lab solved.

**Takeaway:** When both the username and password are concatenated into the same query, commenting out the password clause entirely removes that check. This is the same underlying flaw as Lab 1 — an attacker-controlled string terminator plus a comment token — applied to an authentication check instead of a product filter.

---

## Lab 3: SQL injection attack, querying the database type and version on Oracle
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-oracle

**Vulnerability:** Same injectable category filter as Lab 1, this time on an Oracle backend, used to run a UNION-based query that pulls the database's own version banner instead of product rows.

**Steps:**
1. Determined the query's column count with `category=Lifestyle' ORDER BY 3--` (succeeded) vs. `ORDER BY 4--` (Internal Server Error) → the query returns exactly 2 columns.
2. Oracle requires every `SELECT` to have a `FROM` clause, even for constants, so a plain `UNION SELECT ... FROM dual` wasn't useful here — instead targeted Oracle's built-in `v$version` view, which exposes the version banner as rows:
   ```
   Lifestyle' UNION SELECT banner,NULL FROM v$version--
   ```
3. The response listed each line of the Oracle version banner as if it were a product name → lab solved.

**Takeaway:** `ORDER BY` is the fastest way to fingerprint a UNION injection's column count before attempting the UNION itself. Oracle's mandatory `FROM` clause is a distinguishing quirk versus other engines, and `v$version` (or `dual` for constants) is the standard workaround.

---

## Lab 4: SQL injection attack, querying the database type and version on MySQL and Microsoft
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

**Vulnerability:** Same idea as Lab 3, but on a MySQL backend, which exposes the version through the `@@version` built-in variable rather than a system view.

**Steps:**
1. Confirmed 2 columns via `category=Gifts' ORDER BY 3--` → Internal Server Error.
2. Tried `Gifts' UNION SELECT @@version,NULL--` first — this returned an Internal Server Error even though the syntax looked correct.
3. Realized MySQL's `--` comment syntax requires a trailing space to be recognized as a comment; a bare `--` at the very end of the URL wasn't being parsed as one. Adding a dash-space-dash suffix fixed it:
   ```
   Gifts' UNION SELECT @@version,NULL-- -
   ```
4. The response leaked the full MySQL version string (`8.0.42-0ubuntu0.20.04.1`) → lab solved.

**Takeaway:** MySQL's `--` comment needs a following whitespace character to actually behave as a comment — worth remembering as a gotcha distinct from other database engines, where a trailing `--` alone is normally sufficient.

---

## Lab 5: SQL injection attack, listing the database contents on non-Oracle databases
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

**Vulnerability:** The same UNION-injectable category filter, escalated from reading the DB version to walking the database's own metadata (`information_schema`) to discover an application table and its column names before dumping its contents — since this lab deliberately randomizes the table and column names so they can't just be guessed.

**Steps:**
1. Confirmed 2 columns via `ORDER BY 3--` → Internal Server Error.
2. Enumerated table names: `Pets' UNION SELECT table_name,NULL FROM information_schema.tables--` → returned a long list of PostgreSQL system tables plus one application table, `users_mufixs`.
3. Enumerated that table's columns: `... FROM information_schema.columns WHERE table_name='users_mufixs'--` → found `username_iygwus` and `password_qkptkg`.
4. Dumped the table: `Pets' UNION SELECT username_iygwus,password_qkptkg FROM users_mufixs--` → returned `administrator:hzv1z5z0fde74latbuy6` (plus `carlos` and `wiener`'s rows).
5. Logged in as `administrator` with the recovered password → lab solved.

**Takeaway:** `information_schema` is a standard, cross-vendor (non-Oracle) way to discover a database's own structure — table names, column names, data types — from inside a SQL injection, with no prior knowledge of the schema required. Randomizing names doesn't help if the schema itself is still queryable.

---

## Lab 6: SQL injection attack, listing the database contents on Oracle
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle

**Vulnerability:** Same schema-enumeration technique as Lab 5, but Oracle doesn't expose `information_schema` — it has its own data dictionary views (`all_tables`, `all_tab_columns`) that serve the same purpose.

**Steps:**
1. Confirmed 2 columns via `ORDER BY 3--` → Internal Server Error.
2. Enumerated tables: `Gifts' UNION SELECT table_name,NULL FROM all_tables--` → found the application table `USERS_XVAUBL` among Oracle's many built-in system tables.
3. Enumerated its columns: `... FROM all_tab_columns WHERE table_name='USERS_XVAUBL'--` → found `USERNAME_DCZGVJ` and `PASSWORD_IKSDNX`.
4. Dumped the table: `Gifts' UNION SELECT USERNAME_DCZGVJ,PASSWORD_IKSDNX FROM USERS_XVAUBL--` → returned `administrator:2okfh4lxe3dv194vros3`.
5. Logged in as `administrator` → lab solved.

**Takeaway:** Every major SQL dialect ships some form of queryable self-describing metadata — `information_schema` almost everywhere else, `all_tables`/`all_tab_columns` on Oracle. Knowing the vendor-specific equivalents is what turns "I found an injection point" into "I can walk the entire schema."

---

## Lab 7: SQL injection UNION attack, determining the number of columns returned by the query
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns

**Vulnerability:** A UNION-injectable category filter where the whole task is simply to find the exact column count needed before any UNION-based attack can work at all — no data extraction required.

**Steps:**
1. Binary-searched with `ORDER BY`: `Gifts' ORDER BY 4--` → Internal Server Error; `Gifts' ORDER BY 3--` → valid response with no error.
2. Confirmed with a matching UNION: `Gifts' UNION SELECT NULL,NULL,NULL--` → succeeded (no error, valid page).
3. Lab flipped to solved purely from a syntactically valid UNION with the correct column count — no visible data needed.

**Takeaway:** `ORDER BY <n>--` is a clean, low-noise way to find a query's column count one bisection at a time, since the database will error the moment `n` exceeds the actual number of selected columns. `NULL` is the safe filler value for a UNION probe because it's implicitly compatible with (almost) any column type.

---

## Lab 8: SQL injection UNION attack, finding a column containing text
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text

**Vulnerability:** Same setup as Lab 7, one step further: once the column count is known, not every column necessarily accepts a string value (some may be typed as numeric internally), so each position has to be probed individually before it can be used to exfiltrate text data.

**Steps:**
1. Confirmed 3 columns via `ORDER BY 3--` (ok) / `ORDER BY 4--` (error).
2. Probed column 1: `UNION SELECT 'akLYHi',NULL,NULL--` → Internal Server Error (that column isn't a compatible type for a string literal).
3. Probed column 2: `UNION SELECT NULL,'akLYHi',NULL--` → succeeded, and the marker string `akLYHi` (the exact value the lab asked for) was reflected on the page → lab solved.

**Takeaway:** In a UNION attack, don't assume every column can hold arbitrary text — test each position with a literal string one at a time (replacing `NULL`) until one succeeds without an error. That column becomes the channel for extracting whatever data comes next.

---

## Lab 9: Blind SQL injection with conditional responses
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

**Vulnerability:** The injectable input here is the `TrackingId` cookie, used server-side in a query whose *result* is never shown in the response — no error message, no reflected data, no UNION output. The only observable signal is that a genuine match makes a "Welcome back!" banner appear in the page; anything else looks identical to a normal page load. That single bit of information is enough to reconstruct arbitrary data one true/false question at a time.

**Steps:**
1. Confirmed the injection point and the oracle: `TrackingId=<id>' AND '1'='1` → "Welcome back!" appears (true); `...AND '1'='2` → it doesn't (false).
2. Since `TrackingId` is `HttpOnly`, it's invisible to page JavaScript, so I drove the requests directly with `curl` instead of the browser, setting the `Cookie` header explicitly for full control over each payload.
3. Found the admin password's length via binary search on `(SELECT LENGTH(password) FROM users WHERE username='administrator')>N` — narrowed it down to exactly 20 characters.
4. Extracted the password character by character with nested binary search on `ASCII(SUBSTRING(password,i,1))>=mid` for each position `i` from 1 to 20 (about 7 requests per character instead of up to 95 with linear guessing).
5. Verified the full result in one shot: `...AND(SELECT password FROM users WHERE username='administrator')='nzqwdh42yuu2fq6aenht` → true.
6. Logged in as `administrator` with the recovered password in the browser → lab solved.

**Takeaway:** Blind injection doesn't need visible query output at all — a single reliable true/false signal (a banner, a status code, a redirect, even a timing difference) is enough to reconstruct any piece of data the database holds, one bit at a time. Binary search on length and then on each character's ASCII value turns what sounds like a huge brute-force problem into a small, fast, and fully scriptable one. It's also worth checking whether the injectable parameter is `HttpOnly` before reaching for browser DevTools — if it is, driving requests with `curl` (or Burp) directly is far more reliable than trying to manipulate the cookie from page JavaScript.

---

## Lab 10: SQL injection UNION attack, retrieving data from other tables
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables

**Vulnerability:** The same UNION-injectable category filter as earlier labs, but this time the target table and column names (`users`, `username`, `password`) are fixed and predictable rather than randomized, so the whole attack collapses into a single UNION query once the column count is known.

**Steps:**
1. Confirmed 2 columns via `ORDER BY 3--` → Internal Server Error.
2. Dumped the credentials directly, no schema enumeration needed:
   ```
   Gifts' UNION SELECT username,password FROM users--
   ```
3. The response listed every account, including `administrator:jdmaybh6n5wkbshzcb4k`.
4. Logged in as `administrator` → lab solved.

**Takeaway:** Once a UNION injection's column count and a text-compatible column are known, pulling data from an entirely unrelated table is just a matter of naming it — the query doesn't have to reference anything in the original table at all. This is the payoff that all the column-counting and schema-enumeration groundwork in the earlier labs was building toward.

---

## Overall takeaways from Day 3

- **Concatenating user input into SQL text is the root cause every single time** — whether it lands in a `WHERE` clause, a login check, or a cookie value read server-side, the fix is always the same: parameterized queries, never string-building.
- **`ORDER BY` and per-column string probing are the standard reconnaissance steps before any UNION attack** — they tell you the exact shape a UNION `SELECT` needs before you try to extract real data with it.
- **Database metadata tables (`information_schema` / Oracle's `all_tables` and `all_tab_columns`) turn "I have an injection" into "I can read the entire schema,"** even when table and column names are deliberately randomized.
- **Comment syntax is not universal** — MySQL's `--` needs a trailing space to actually start a comment, which is an easy, silent source of an "Internal Server Error" that looks like a dead end but isn't.
- **When there's no visible output at all, the injection isn't dead — it's blind.** A single reliable true/false signal (a banner, a status code, a timing gap) is enough to reconstruct arbitrary data via binary search, and it's usually far faster than it sounds.
- **Not every browser-accessible tool applies to every scenario** — an `HttpOnly` cookie used as the injection point can't be read or written from page JavaScript, which is a good reminder to reach for `curl` (or a proxy like Burp) when the browser itself gets in the way of the attack.
