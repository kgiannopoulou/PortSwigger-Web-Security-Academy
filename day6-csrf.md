# PortSwigger Web Security Academy — Cross-Site Request Forgery (Day 6)

My notes and write-ups from Day 6 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), and **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), I moved on to the **Cross-Site Request Forgery (CSRF)** topic and worked through 9 labs (1 Apprentice-level, 8 Practitioner-level).

## What is "cross-site request forgery"?

CSRF tricks a logged-in victim's browser into issuing a request to a vulnerable site on the attacker's behalf, relying on the browser automatically attaching the victim's session cookie to that request. Every lab below is a variation on the same three ingredients the CSRF write-up on PortSwigger describes: a relevant state-changing action (here, always "change my email address"), cookie-based session handling, and no unpredictable parameter the attacker can't guess. The labs mostly differ in *which* anti-CSRF defense is in place and *how* it's implemented badly — a missing token check, a token that isn't bound to the session, a `SameSite` cookie restriction that can be routed around, or a `Referer` check that's either skippable or naively implemented. The recurring lesson: a defense that looks correct in isolation often has an edge case — a method it forgets to check, a header it assumes is always present, a redirect it doesn't realize is same-site — that fully defeats it.

Each lab uses the same basic exploit shape: an auto-submitting HTML form hosted on the PortSwigger exploit server, targeting the lab's `/my-account/change-email` endpoint, delivered to the lab's simulated victim (who is already logged in as `wiener`).

---

## Lab 1: CSRF vulnerability with no defenses
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/csrf/lab-no-defenses

**Vulnerability:** The email-change form has no CSRF token, no `SameSite` cookie restriction, and no `Referer` check at all — literally nothing stopping a cross-site request from succeeding.

**Steps:**
1. Logged in as `wiener:peter` and confirmed the change-email form posts to `/my-account/change-email` with just an `email` parameter — no hidden token field.
2. On the exploit server, hosted an auto-submitting HTML form targeting that endpoint with `email=pwned@evil-user.net`.
3. Clicked **Deliver exploit to victim**.

**Takeaway:** The one gotcha here wasn't the exploit itself — it was testing methodology. I first changed my *own* session's email directly to prove the payload worked, then delivered to the victim without resetting it. Since the victim shares the same underlying account state, the "solved" check (which appears to be delta-based — did this request actually *change* something) didn't trigger because the email was already at the target value. Resetting the email back to its original value before the real delivery fixed it immediately. Good reminder to keep proof-of-concept testing and the actual delivered attack separate.

---

## Lab 2: CSRF where token validation depends on request method
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-request-method

**Vulnerability:** The server correctly validates the CSRF token on POST requests, but skips validation entirely if the request uses GET instead.

**Steps:**
1. Confirmed the change-email form normally POSTs with a `csrf` hidden field.
2. Built an exploit form using `method="GET"` instead of POST, targeting the same endpoint with just the `email` parameter.
3. Delivered the exploit — the server processed the GET request and changed the email without ever checking for a token.

**Takeaway:** A CSRF token defense that's only wired up for one HTTP method is no defense at all if the underlying handler accepts other methods too. Always check whether a "protected" endpoint enforces the same rules regardless of verb.

---

## Lab 3: CSRF where token validation depends on token being present
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-validation-depends-on-token-being-present

**Vulnerability:** The server validates the `csrf` token correctly when it's present in the request, but skips validation entirely if the parameter is omitted rather than just left blank.

**Steps:**
1. Confirmed the normal request includes a `csrf` hidden field alongside `email`.
2. Built an exploit form that only submits the `email` field, leaving the `csrf` parameter out of the request body entirely (not just empty).
3. Delivered the exploit — validation was skipped because there was no token parameter to check at all.

**Takeaway:** "Validate the token if present" is a very different (and much weaker) rule than "require a valid token." Removing a parameter outright is a distinct bypass from sending it empty, and defenses need to handle both.

---

## Lab 4: CSRF where token is not tied to user session
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-not-tied-to-user-session

**Vulnerability:** The application generates and checks CSRF tokens against a global pool of issued tokens rather than binding each token to the session that requested it — so *any* valid token accepted by the server will pass, regardless of whose session it was originally issued to.

**Steps:**
1. Logged in as `wiener:peter` and grabbed the valid `csrf` token value from my own session's change-email form.
2. Built an exploit form containing that token as a hidden field alongside the attacker's target `email` value.
3. Delivered the exploit — the victim's browser submitted the attacker's own valid token, which passed validation since the server only checks "does this token exist in the pool," not "does this token belong to this session."

**Takeaway:** A CSRF token is only as strong as its binding to the user's session. If the server can't tell *whose* token it's looking at, an attacker can simply harvest their own valid token and hand it to the victim.

---

## Lab 5: CSRF where token is duplicated in cookie
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-token-validation/lab-token-duplicated-in-cookie

**Vulnerability:** This is the "double submit" CSRF defense: the server doesn't track issued tokens server-side at all, it just checks that the `csrf` request parameter matches the `csrf` cookie value. Since there's no server-side state, an attacker doesn't need to know a "real" token — they just need the parameter and cookie to match, and a way to plant a cookie of their choosing in the victim's browser.

**Vulnerability detail:** The double-submit pattern is only as strong as the assumption that an attacker can't set arbitrary cookies on the target's origin. This lab (like the article describing it) relies on some other cookie-setting behavior on the site to plant the attacker's chosen value into the victim's `csrf` cookie, after which the matching value is submitted as the request parameter.

**Takeaway:** "Double submit" CSRF protection trades server-side state for an assumption — that the attacker can't write cookies to the victim's browser for that origin — which doesn't hold if *any* other feature on the site (even an unrelated one, even on a sibling subdomain) lets you set cookies. This lab had already been solved in an earlier practice session, and I've folded the underlying technique into today's write-up for completeness rather than re-solving it from scratch.

---

## Lab 6: SameSite Lax bypass via method override
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-lax-bypass-via-method-override

**Vulnerability:** The session cookie uses `SameSite=Lax` (the modern browser default), which blocks the cookie on cross-site POST requests but still allows it on cross-site *top-level GET navigations*. The application also supports a `_method` override parameter (common in some web frameworks) that lets a GET request masquerade as a POST for routing purposes.

**Steps:**
1. Confirmed the change-email endpoint normally requires POST, and that `SameSite=Lax` would ordinarily block a cross-site POST from carrying the session cookie.
2. Built an exploit form using `method="GET"`, with hidden fields for both `email` and `_method=POST`.
3. Delivered the exploit — because it's a top-level GET navigation, Lax allowed the cookie through; the server then honored `_method=POST` and processed it as if it were a real POST.

**Takeaway:** `SameSite=Lax` only protects methods it actually restricts (POST, etc.) — if the framework offers a way to simulate a blocked method using an allowed one, that override completely undermines the SameSite protection.

---

## Lab 7: SameSite Strict bypass via client-side redirect
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions/lab-samesite-strict-bypass-via-client-side-redirect

**Vulnerability:** `SameSite=Strict` blocks the cookie on *any* cross-site request, including top-level GET navigations — much stronger than Lax. However, browsers determine "same-site" based on the page that *initiates* a given request, not the original attacker page. If the target site has a client-side (JavaScript-driven) redirect gadget that reads its destination from an attacker-controllable parameter, an attacker can perform an initial cross-site navigation to that gadget (which needs no cookie to load), and let the site's *own* script perform the second, same-site navigation to the real target — which the browser now treats as same-site and attaches the Strict cookie to.

**Vulnerability detail:** Unlike a server-side redirect (which the browser correctly still treats as originating cross-site), a client-side redirect is invisible to the browser's SameSite bookkeeping — it just looks like an ordinary same-site request once the JavaScript kicks off.

**Takeaway:** `SameSite=Strict` is the strongest cookie-level CSRF defense available, but it's undermined by any on-site "open redirect" gadget, since the browser's same-site determination is based on the *immediate* referring page, not the original cross-site origin the user actually came from. This lab had already been solved in an earlier practice session; I've documented the technique here rather than re-running it.

---

## Lab 8: CSRF where Referer validation depends on header being present
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-depends-on-header-being-present

**Vulnerability:** The server checks that the `Referer` header matches its own domain when the header is present, but skips validation entirely if the header is missing from the request.

**Steps:**
1. Built the usual auto-submitting exploit form targeting `/my-account/change-email`.
2. Added `<meta name="referrer" content="never">` in the exploit page's `<head>`, which instructs the browser to omit the `Referer` header entirely on the resulting request.
3. Delivered the exploit — with no `Referer` header to check, the server skipped validation and processed the request.

**Takeaway:** Browsers give pages fine-grained control over whether the `Referer` header is sent at all, via the `Referrer-Policy` meta tag. Any "validate Referer if present" logic is trivially defeated by simply not sending one.

---

## Lab 9: CSRF with broken Referer validation
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses/lab-referer-validation-broken

**Vulnerability:** The server validates the `Referer` header, but does so naively — checking only that the lab's own domain appears *somewhere* in the header, rather than validating it's actually the origin.

**Steps:**
1. Hosted the exploit at a path on the exploit server whose URL itself contained the lab's domain name (e.g. `/exploit/<lab-id>.web-security-academy.net`), so that the naive substring check would pass against the resulting `Referer`.
2. Added a `Referrer-Policy: unsafe-url` response header on the exploit page, since browsers strip the path/query string from cross-origin `Referer` headers by default — this header forces the full URL (including the embedded lab domain) to be sent.
3. Delivered the exploit — the `Referer` header contained the exploit server's own domain *plus* the lab's domain as a path segment, which was enough to satisfy the naive substring check.

**Steps (debugging note):** My first attempt put the lab domain in the exploit URL's *query string* rather than its path. The exploit server's delivery mechanism appends a trailing slash to the stored URL when dispatching to the victim, which corrupted the query string and returned a 404 instead of serving the payload. Moving the domain into the path (where a trailing slash is harmless) fixed it.

**Takeaway:** A `Referer` check that only does a substring match instead of properly parsing the URL's origin can be satisfied by putting the expected domain *anywhere* in the attacker's URL — as a subdomain, a path segment, or (if the site doesn't strip it) a query string. Also worth remembering: browsers default to stripping the query string from cross-origin `Referer` headers for privacy, so an attacker relying on a query-string bypass needs `Referrer-Policy: unsafe-url` to force the full URL through.

---

## Labs not attempted today

Two labs in this topic were left out of today's run, both for the same reason — they require tooling or techniques that don't fit a fast, browser-automation-only workflow:

- **SameSite Strict bypass via sibling domain** — this lab's actual vulnerability is cross-site WebSocket hijacking (CSWSH), and solving it requires exfiltrating chat history to a Burp Collaborator server, which needs Burp Suite Pro rather than a plain browser.
- **CSRF where token is tied to non-session cookie** — solving this requires finding an on-site cookie-setting gadget and using CRLF/cookie injection to plant a forged `csrfKey` cookie in the victim's browser. This is the same lab that caused an earlier practice session on this topic to be abandoned partway through after repeated failed attempts — flagging it here again rather than re-grinding it.

---

## A note on testing methodology

Several of the token- and cookie-based labs above are easy to accidentally "solve against yourself" rather than the intended victim, since the lab's simulated victim shares the same underlying account state as the test account you're given. Lab 1's write-up above covers the specific gotcha (resetting state before the real delivery) in more detail — it's a pattern worth watching for across the whole CSRF topic, not just that one lab.
