# PortSwigger Web Security Academy — Authentication (Day 2)

My notes and write-ups from Day 2 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After finishing **Access Control** on [Day 1](README.md), I moved on to the **Authentication** topic and worked through 10 labs (8 Practitioner-level, 2 Expert-level).

## What is "Authentication"?

Authentication is about verifying *who* a user is — logging in, staying logged in, resetting a password, proving a second factor. Every lab below breaks a different link in that chain: the login form itself, the brute-force protections meant to guard it, "remember me" cookies, password-reset flows, and two-factor verification. The recurring lesson: **authentication logic is only as strong as its weakest, most overlooked branch** — a subtly different error message, a header the app trusts a little too much, a lockout that resets too easily, or a defense that counts the wrong thing (requests instead of actual guesses).

---

## Lab 1: Username enumeration via response timing
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing

**Vulnerability:** The login endpoint only hashes the submitted password when the username actually exists (to compare it against the stored hash). For a non-existent username, it skips hashing and returns immediately — creating a measurable timing gap between "valid username, wrong password" and "invalid username" that gets bigger the longer the submitted password is.

**Steps:**
1. Sent a login request with a very long password (~100 characters) for a known-valid username vs. an obviously invalid one, and timed the responses — the valid username consistently took ~500ms longer.
2. Looped the same request across the full candidate username list (one request per username, same long password each time), and picked out the one response that was dramatically slower than the rest. Repeated it a few times to rule out network jitter.
3. The lab also enforces an IP-based lockout after too many failed logins — bypassed by sending a different `X-Forwarded-For` value on every request, since the app trusts that header for its rate-limiting IP check.
4. Once the valid username was confirmed, brute-forced its password against the candidate password list, checking for a `302` (successful login) response instead of the login page reloading.
5. Logged in with the identified username/password → lab solved.

**Takeaway:** Timing side-channels leak information even when every response *looks* identical. Defenses also need to be consistent about what they treat as "the client's IP" — trusting a spoofable header like `X-Forwarded-For` for a security control defeats the control entirely.

---

## Lab 2: Username enumeration via subtly different responses
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses

**Vulnerability:** The generic "wrong username or password" error message isn't actually identical for every code path. A copy-paste/typo bug means the branch for "valid username, wrong password" builds the string slightly differently than the branch for "invalid username" — one ends in a period, the other has a trailing space instead.

**Steps:**
1. Sent the same obviously-wrong password against every candidate username, and captured the *exact* error message text from each response.
2. Grouped the responses by message text — out of 101 usernames, 100 returned the byte-identical standard message, and exactly one returned a variant with a trailing space and no period.
3. That one username was confirmed valid. Brute-forced its password against the candidate list, checking for a redirect (`302`) instead of the error page.
4. Logged in → lab solved.

**Takeaway:** A response doesn't have to look *different* to a human to leak account existence — a single stray whitespace character, inconsistent capitalization, or a different HTTP header can all serve as an oracle. Safe error handling means guaranteeing the exact same code path and exact same string constant regardless of which check actually failed.

---

## Lab 3: Broken brute-force protection, IP block
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/password-based/lab-broken-bruteforce-protection-ip-block

**Vulnerability:** The app blocks an IP after 3 incorrect logins in a row — but the "in a row" counter resets to zero after *any* successful login from that IP, even a login to an unrelated, low-privilege account that has nothing to do with the account being attacked.

**Steps:**
1. Confirmed that logging in with my own valid credentials, at any point, reset the failed-attempt counter back to zero.
2. Ran through the candidate password list against the victim's account, but interleaved every single guess with one login using my own valid credentials — so the sequence was: guess, reset, guess, reset, guess, reset... never accumulating more than one failed attempt in a row.
3. This kept the attack permanently below the 3-strikes threshold, so the IP block never triggered, and the correct password turned up quickly.
4. Logged in as the victim → lab solved.

**Takeaway:** Brute-force lockouts must be scoped to the *specific account under attack*, not to "recent activity from this IP" in general — otherwise anyone who also controls one legitimate low-privilege account can use it to keep resetting the counter indefinitely.

---

## Lab 4: Username enumeration via account lock
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock

**Vulnerability:** The account-lockout feature itself leaks whether a username is valid. Submitting the same wrong password against a non-existent username just returns the same generic error forever. Submitting it against a *real* account eventually trips the lockout, and only then does the response text change to an account-locked message — so the mere appearance of that message confirms the account exists. A second bug layers on top: even while an account is locked, the response for the *correct* password (still rejected, since it's locked) differs from the response for a wrong one, leaking the valid password too.

**Steps:**
1. Sent 5 identical wrong-password attempts against every candidate username, and compared the final response message for each.
2. 100 usernames kept returning the standard invalid-credentials message; exactly one returned "You have made too many incorrect login attempts" — confirming that username was valid and now locked.
3. While that account was still in its lock window, looped the full candidate password list against it. Almost all attempts returned the lockout message, but exactly one attempt returned a response with **no error message at all** — a side effect of the app checking password correctness before it checks lock status.
4. Waited out the 1-minute lock window, then logged in normally with the identified username and password → lab solved.

**Takeaway:** Any security feature — including the lockout mechanism meant to *stop* brute-forcing — can become a username-enumeration oracle if its behavior, message, or timing differs based on whether the target account is real.

---

## Lab 5: Brute-forcing a stay-logged-in cookie
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie

**Vulnerability:** The "Stay logged in" cookie is `base64(username + ":" + MD5(password))` — an unsalted, client-verifiable hash. Since the hash algorithm and format are entirely knowable from inspecting your own cookie, anyone can forge a *candidate* cookie for any username by hashing a guessed password themselves, with no login attempt against the server at all.

**Steps:**
1. Logged in with "Stay logged in" checked and decoded the resulting cookie to confirm the `username:MD5(password)` format.
2. Implemented MD5 client-side (browsers don't expose it natively) and validated it against known test vectors.
3. For each candidate password: computed its MD5 hash, built `base64("carlos:" + hash)`, set it directly as the cookie, and requested the victim's account page — using the presence of an "Update email" button (only rendered on your *own* authenticated account) as the success/failure oracle.
4. Found the matching password and confirmed access to the victim's account page → lab solved.

**Takeaway:** Never build a persistent "remember me" token from a reversible, unsalted, deterministic function of guessable inputs. Because the token is entirely client-side computable, there's no way to rate-limit this attack server-side at all — it's pure offline computation.

---

## Lab 6: Offline password cracking
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking

**Vulnerability:** Same weak stay-logged-in cookie format as Lab 5, chained with a stored XSS vulnerability in the blog comment field. Neither bug alone is catastrophic — together, they let an attacker steal a victim's real cookie (and therefore their real password hash) without ever needing to guess anything about the victim directly.

**Steps:**
1. Confirmed the comment field renders `<script>` tags unescaped.
2. Posted a comment containing a script that redirects the victim's browser to my exploit server with `document.cookie` appended to the URL.
3. The lab's simulated victim viewed the post shortly after, triggering the script — the exploit server's access log captured the victim's `stay-logged-in` cookie.
4. Decoded the cookie to get `username:MD5hash`, then cracked the hash "offline" (in a real scenario, via a wordlist tool like hashcat, or by checking whether the hash is already publicly indexed since MD5 has no salt).
5. Logged in normally with the cracked password, went to "My account," and deleted the account (the lab's specific solve condition) → lab solved.

**Takeaway:** A low-severity XSS in something as small as a comment box becomes a full account-takeover primitive when chained with an unrelated weak-cookie design. This is also a clean illustration of why "offline" cracking matters: once an attacker has the hash, all of the login form's rate-limiting is irrelevant — the guessing happens locally, with unlimited attempts.

---

## Lab 7: Password reset poisoning via middleware
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-poisoning-via-middleware

**Vulnerability:** The app runs behind middleware/a reverse proxy and builds password-reset links using the `X-Forwarded-Host` header instead of a fixed, trusted hostname. Since that header is entirely attacker-controlled, the reset link's *destination* can be poisoned while the token embedded in it stays genuinely valid.

**Steps:**
1. Triggered a normal password reset for my own account to see the real link format: `.../forgot-password?temp-forgot-password-token=<token>`.
2. Noted my exploit server's URL for this lab instance.
3. Sent a password-reset request for the victim's username, adding a header: `X-Forwarded-Host: <my-exploit-server-domain>`.
4. The app emailed the victim a reset link built with my exploit-server host instead of the real one. Since the lab's victim "carelessly clicks any link," they visited it automatically.
5. Checked my exploit server's access log and found the victim's real, valid token sitting in the captured request.
6. Replayed that exact token against the **real** application's reset endpoint (not the poisoned one) — since only the link's *host* was poisoned, the token itself was untouched and still valid there.
7. Set a new password for the victim's account and logged in → lab solved.

**Takeaway:** Never build absolute URLs (password resets, invite links, redirects) from client-controlled headers like `Host` or `X-Forwarded-Host` without a strict allowlist behind a properly configured trusted proxy. A cryptographically strong token is irrelevant if the *delivery channel* pointing at it is attacker-controllable.

---

## Lab 8: Password brute-force via password change
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-brute-force-via-password-change

**Vulnerability:** Two bugs chained. First, an IDOR: the change-password endpoint takes the target `username` as a plain hidden form field rather than deriving it from the session, so an authenticated attacker can submit a password-change attempt *for someone else's account*. Second, a response-message oracle: the endpoint validates in a fixed order and returns a different error depending on which check failed — "current password is incorrect" vs. "new passwords do not match" — and the account-lock logic only triggers when the two new-password fields actually match.

**Steps:**
1. Logged in with my own account and inspected the change-password form — found the hidden `username` field alongside `current-password` and the two new-password fields.
2. Looped the candidate password list, POSTing to the change-password endpoint each time with the victim's username, a candidate as `current-password`, and two *different*, throwaway values for the new password (so the lockout condition — matching new passwords — never triggers).
3. Watched for the response to flip from "current password is incorrect" to "new passwords do not match" — that flip is the signal that the current-password guess was correct.
4. Logged out, logged back in as the victim with the identified password → lab solved.

**Takeaway:** Any authenticated action that accepts a target identifier from client input, rather than deriving it from the session, is a broken access control bug on its own. Combined with a multi-stage validation flow that leaks *which* stage failed via distinct error text, it becomes a full password-guessing oracle that completely bypasses the login form's own brute-force protections.

---

## Lab 9: Broken brute-force protection, multiple credentials per request
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/authentication/password-based/lab-broken-brute-force-protection-multiple-credentials-per-request

**Vulnerability:** The login endpoint accepts credentials as JSON. Its brute-force defense counts *requests*, not actual credential checks — and the backend happily accepts an **array of passwords** instead of a single string, checking every element in that array against the account and succeeding if any one of them matches. That collapses an entire wordlist attack into a single request.

**Steps:**
1. Confirmed the login endpoint accepts `Content-Type: application/json`.
2. Sent one `POST /login` request with `{"username": "carlos", "password": [...the entire candidate password list...]}` instead of a single string.
3. Got a `302` back on the very first request — the server found a match somewhere in the array and authenticated in that one response.
4. Loaded the account page → lab solved, no enumeration or timing tricks needed at all.

**Takeaway:** This is really an input-validation/type-confusion bug (accepting an array where a scalar was expected) with catastrophic authentication consequences. Any brute-force defense that counts HTTP requests rather than individual credential comparisons is vulnerable to this exact pattern. Fix: strictly validate that fields like `password` are single strings, and count failed comparisons — not requests — toward the lockout threshold.

---

## Lab 10: 2FA bypass using a brute-force attack
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/authentication/multi-factor/lab-2fa-bypass-using-a-brute-force-attack

**Vulnerability:** Given valid credentials, the 4-digit 2FA code has no real protection against brute-forcing. The app tries to compensate with a crude defense — two wrong code submissions in a row invalidate the session — but that only protects a single session. Since the attacker already has the valid password (the entire premise of needing a *second* factor), simply logging back in resets the attempt count for free.

**Steps:**
1. Confirmed that one wrong 2FA code still leaves the session usable for a second attempt, but a second wrong code breaks the session (subsequent requests to the 2FA endpoint start erroring).
2. Built an automated loop that, for every 2 candidate codes: logs in fresh with the known valid password, submits the first code guess, and — if that fails — submits a second guess in the same still-valid session before starting over.
3. Ran through the code space sequentially (no concurrency, since session state has to stay coherent) starting from `0000`.
4. Landed on the correct 4-digit code well within the first pass, which returned a `302` and left the session fully authenticated.
5. Loaded the account page → lab solved.

**Takeaway:** A per-session lockout on MFA attempts is close to useless against an attacker who already has valid primary credentials — which is precisely the threat model 2FA exists to defend against. Real protection has to be tied to the *account*, not the session: a small, fixed total number of attempts, or backoff keyed to the username across every session, not something a fresh login can reset.

---

## Overall takeaways from Day 2

- **Error messages, timing, and even byte-level formatting can all leak information.** "Looks identical" isn't the same as "is identical" — a generic error needs to come from the exact same code path every time, with no exceptions for edge cases.
- **Security features can themselves become oracles.** Lockouts, account-lock messages, and multi-stage validation flows all leaked information in these labs precisely because they behaved *differently* depending on secret internal state.
- **Rate-limiting has to count the right thing.** Counting IPs instead of accounts, requests instead of credential comparisons, or sessions instead of accounts all created bypassable brute-force "protections."
- **Never trust client-supplied headers or hidden fields for security-relevant decisions** — `X-Forwarded-For`, `X-Forwarded-Host`, and a hidden `username` field were all abused this way.
- **Weak cryptographic choices in "convenience" features (like a stay-logged-in cookie) can undermine an otherwise solid login flow** — especially when they're client-verifiable and unsalted.
- 2FA is only as strong as the rate-limiting protecting the second factor itself; if the code can be brute-forced faster than it expires, it isn't adding real protection against an attacker who already has the password.
