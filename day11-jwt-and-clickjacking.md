# PortSwigger Web Security Academy — JWT Attacks & Clickjacking (Day 11)

My notes and write-ups from Day 11 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), **SSRF & Path Traversal** on [Day 7](day7-ssrf-and-path-traversal.md), **XXE Injection & OS Command Injection** on [Day 8](day8-xxe-and-os-command-injection.md), **File Upload Vulnerabilities & Information Disclosure** on [Day 9](day9-file-upload-and-information-disclosure.md), and **Prototype Pollution** on [Day 10](day10-prototype-pollution.md), today's topic is **JWT Attacks** — the full 8-lab topic — plus 2 **Clickjacking** labs to round out the day.

## What are JWT attacks?

JSON Web Tokens (JWTs) are signed, self-contained tokens commonly used for authentication and session handling: a header, a payload of claims, and a signature, base64url-encoded and dot-separated. Because the server trusts the payload's contents without re-checking them against any server-side state, the entire security model rests on the signature actually being verified correctly. JWT attacks exploit implementation flaws in that verification step — anything from a server that never checks the signature at all, to one that can be tricked into verifying a forged token against a key of the attacker's choosing — to forge tokens with arbitrary claims (usually `sub: administrator`) and hijack another user's privileges.

## What is clickjacking?

Clickjacking tricks a logged-in victim into clicking something on a target site without realizing it, usually by rendering that site in an invisible or disguised `<iframe>` on an attacker-controlled page and positioning a decoy "click me" element exactly over a sensitive button (like "Delete account"). Because the click really lands on the target site in the victim's own authenticated session, it bypasses defenses like CSRF tokens entirely — the browser sends a completely legitimate, correctly-tokened request, the user just didn't mean to send it.

## Lab 1: JWT authentication bypass via unverified signature
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature

**Vulnerability:** The server decodes the JWT session cookie to read claims but never actually verifies the signature, so any syntactically valid token is accepted regardless of what signed it.

**Steps:**
1. Logged in as `wiener:peter` and captured the RS256-signed session cookie.
2. Decoded the payload, changed `sub` from `wiener` to `administrator`, and re-encoded it with a brand new HS256 signature signed under an arbitrary throwaway key (since the server never checks it, the signature's validity is irrelevant — only its presence).
3. Sent the forged cookie to `/admin`, got a `200` with delete links for both users, and requested `/admin/delete?username=carlos` to solve the lab.

**Takeaway:** A JWT library that exposes separate `decode()` and `verify()` functions is a trap for developers in a hurry — calling only `decode()` silently turns the "signature" into decorative Base64, no forging cleverness required at all.

---

## Lab 2: JWT authentication bypass via flawed signature verification
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification

**Vulnerability:** The server does verify signatures for signed tokens, but also honors the JWS `alg: none` "unsecured JWT" mode, letting an attacker submit a completely unsigned token that the server accepts as authoritative.

**Steps:**
1. Logged in as `wiener`, captured the RS256 session cookie, and changed `sub` to `administrator`.
2. Built a new token with header `{"alg":"none","typ":"JWT"}` and the modified payload, leaving the signature segment empty (token ending in a trailing dot).
3. Sent it to `/admin` — `200 OK` with both delete links — and deleted `carlos` to solve the lab.

**Takeaway:** Supporting the `none` algorithm at all is inherently dangerous in a JWT library; it exists for niche use cases (unsecured tokens passed over an already-trusted channel) and should be disabled outright in anything that authenticates users.

---

## Lab 3: JWT authentication bypass via weak signing key
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key

**Vulnerability:** The server signs tokens with HS256 using a short, guessable secret instead of a long random one, making the key brute-forceable offline from a single captured token.

**Steps:**
1. Logged in as `wiener` and captured the HS256 session cookie.
2. Brute-forced the HMAC secret locally in Python against the public `wallarm/jwt-secrets` wordlist (~104k common JWT secrets), computing `HMAC-SHA256(secret, header.payload)` for each candidate and comparing to the token's real signature — found the secret (`secret1`) in under a second, on the 56th candidate.
3. Changed `sub` to `administrator` and re-signed the token with the recovered secret, then used it to delete `carlos` via `/admin`.

**Takeaway:** A JWT's signature is only as strong as its secret — since HS256 treats the secret as an arbitrary string rather than a fixed-size cryptographic key, a short or dictionary-word secret is crackable offline in milliseconds once you have even one valid token to check candidates against.

---

## Lab 4: JWT authentication bypass via jwk header injection
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection

**Vulnerability:** The server accepts a `jwk` (JSON Web Key) parameter embedded directly in the JWT header and uses whatever key is embedded there to verify the signature, instead of restricting verification to a fixed, trusted key.

**Steps:**
1. Logged in as `wiener`, captured the token, and set `sub` to `administrator`.
2. Generated a fresh 2048-bit RSA keypair locally and embedded the public key as a `jwk` object directly in the forged token's header (with a matching `kid`), then signed the token with the corresponding private key.
3. Sent the self-signed token to `/admin` — the server dutifully verified the signature against the attacker-supplied key embedded in the token itself, returned `200`, and `carlos` was deleted to solve the lab on the first attempt.

**Takeaway:** Letting the token specify its own verification key defeats the entire purpose of a signature — verification must only ever use a key the server already trusts out-of-band, never one supplied by the token being verified.

---

## Lab 5: JWT authentication bypass via jku header injection
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection

**Vulnerability:** Instead of embedding the key directly, the server accepts a `jku` (JWK Set URL) header pointing to *where* to fetch the verification key, and will fetch and trust a key from any URL supplied — including an attacker-controlled one.

**Steps:**
1. Logged in as `wiener`, captured the token, and generated a fresh RSA keypair.
2. Hosted a JWKS document exposing the public key at `/jwks.json` on the lab's own exploit server (`Content-Type: application/json`).
3. Forged a token with `sub: administrator` and a `jku` header pointing at that hosted JWKS URL, signed with the matching private key, and sent it to `/admin` — `200 OK`, admin panel accessible, `carlos` deleted to solve the lab.

**Takeaway:** `jku` has the same fundamental flaw as `jwk` one layer removed — trusting a URL supplied inside the token to fetch the verification key is just as exploitable as trusting an embedded key, since the attacker controls both equally. A real fix requires a strict server-side allowlist of trusted key-set hosts.

---

## Lab 6: JWT authentication bypass via kid header path traversal
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal

**Vulnerability:** The server uses the JWT's `kid` (Key ID) header to look up a key file on disk by path, without sanitizing it — letting an attacker traverse to an arbitrary, predictable file and use its contents as the HMAC signing key.

**Steps:**
1. Logged in as `wiener` and captured the HS256 token.
2. Set `sub` to `administrator` and set the header's `kid` to a directory-traversal path pointing at `/dev/null` (`../../../../../../../dev/null`) — a file guaranteed to exist and be empty on the underlying Linux server.
3. Signed the token with HMAC-SHA256 using an empty string as the key (matching the empty contents of `/dev/null`) and sent it to `/admin` — `200 OK` on the first attempt, `carlos` deleted to solve the lab.

**Takeaway:** `kid` is just as dangerous as `jwk`/`jku` if it's used to build a filesystem path without validation — and `/dev/null` is a uniquely convenient traversal target for this exact class of bug, since "sign with an empty-string secret" requires no guessing at all.

---

## Lab 7: JWT authentication bypass via algorithm confusion
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion

**Vulnerability:** The server normally signs tokens with RS256 (asymmetric: private key signs, public key verifies), but its verification code accepts whatever algorithm the token's own header claims — so a token can be resigned with HS256 (symmetric: same key signs and verifies) and, if the server can be tricked into using its own *public* key as the HMAC secret, the server will "verify" its own forged signature successfully.

**Steps:**
1. Found the server's RSA public key exposed at a standard `/jwks.json` endpoint on the lab app itself.
2. Converted the JWK's `n`/`e` values into a PEM-encoded RSA public key locally.
3. Logged in as `wiener`, set `sub` to `administrator`, and signed a new token with `alg: HS256`, using the raw PEM bytes of the server's own public key as the HMAC secret.
4. Sent it to `/admin` — `200 OK` on the first attempt, since the server verified the HS256 signature using the same public key bytes as the HMAC secret, deleted `carlos` to solve the lab.

**Takeaway:** Never let the token's `alg` header dictate which verification code path runs — a server must pin the expected algorithm server-side. Exposing the RSA public key (necessary for *verification* in normal RS256 use) becomes a critical vulnerability the moment `alg` is attacker-controlled, since asymmetric "public" key material becomes reusable as a symmetric secret.

---

## Lab 8: JWT authentication bypass via algorithm confusion with no exposed key
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/jwt/algorithm-confusion/lab-jwt-authentication-bypass-via-algorithm-confusion-with-no-exposed-key

**Vulnerability:** Same RS256→HS256 algorithm confusion flaw as Lab 7, except this server doesn't expose its public key anywhere — it has to be mathematically derived from ordinary, already-issued signed tokens before the same attack can be carried out.

**Steps:**
1. Confirmed no `/jwks.json` or `/.well-known/` endpoint existed on this instance.
2. Logged in three separate times a few seconds apart to collect three distinct, validly RS256-signed tokens (each with a different `exp` claim, so a different signed message each time) from the same 2048-bit signing key.
3. Derived the server's RSA public modulus `n` locally using the public-key-recovery technique for RSA PKCS#1 v1.5 signatures: for each token, computed the exact (unreduced) big integer `signature^65537 − EMSA-PKCS1-v1.5(message)`, which is always an exact multiple of the true modulus `n`; then took the GCD across three such values — the GCD converges on `n` itself (here after stripping one small cofactor of `2`, landing on a clean 2048-bit modulus). Used `gmpy2` for the big-integer arithmetic since raw Python `pow()` on a ~2048-bit base to the 65537 power without a modulus is a ~16 MB intermediate integer and was far too slow to be practical; `gmpy2`'s GMP-backed exponentiation finished the whole derivation in under two seconds.
4. Built a PEM public key from the derived `n` and the standard exponent `65537`, then repeated the exact Lab 7 attack: forged an HS256 token with `sub: administrator`, signed with the derived public key's PEM bytes as the HMAC secret.
5. The lab's cloud instance had gone idle and recycled to a fresh container (with a new signing key) partway through — re-collected three tokens from the new instance and re-ran the derivation in about 30 seconds. Sent the new forged token to `/admin` — `200 OK` on the first attempt, `carlos` deleted to solve the lab.

**Takeaway:** Not exposing the public key doesn't actually protect an RS256 (or any PKCS#1 v1.5) implementation from algorithm confusion — anyone who can collect a couple of ordinary signed tokens can recover the public modulus purely from math, since `signature^e mod n` is publicly verifiable by design. The only real fix is the same as Lab 7: pin the expected algorithm server-side and never derive it from attacker-controlled input.

---

## Lab 9: Basic clickjacking with CSRF token protection
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/clickjacking/lab-basic-csrf-protected

**Vulnerability:** The account page's "Delete account" action is protected by a CSRF token, but the page sets no framing defense (`X-Frame-Options` / `frame-ancestors`), so it can be embedded in an invisible iframe and clicked by an unwitting logged-in victim — the real, correctly-tokened request goes through, entirely defeating the CSRF protection.

**Steps:**
1. Logged in as `wiener` and located the "Delete account" button on `/my-account`.
2. On the lab's exploit server, hosted a page with a near-transparent (`opacity: 0.0001`) 500×1000px iframe of `/my-account`, and a decoy `<div>Click me</div>` positioned `absolute` and stacked *underneath* the iframe (`z-index` lower), sized and positioned to exactly cover the real "Delete account" button.
3. Getting the pixel alignment right took a few iterations: the button's Y-position shifts noticeably at the iframe's narrower 500px render width versus a normal full-width browser tab (the header/logo wraps differently), so a naive full-width measurement was off by tens of pixels. Verified the true alignment by temporarily setting the iframe to partial opacity via the console and visually confirming a semi-transparent red overlay `div` lined up with the button before reverting to full transparency.
4. Clicked "Deliver exploit to victim" — the simulated victim's click on the decoy landed on the real "Delete account" button underneath, and the account was deleted, solving the lab.

**Takeaway:** A CSRF token proves a request came from the site's own page, but says nothing about whether the *user* meant to send it — clickjacking sidesteps CSRF defenses entirely by getting the legitimate page to generate the legitimate, correctly-tokened request itself. The only real defense is preventing framing in the first place (`X-Frame-Options: DENY` or a `frame-ancestors` CSP directive).

---

## Lab 10: Clickjacking with a frame buster script
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/clickjacking/lab-frame-buster-script

**Vulnerability:** The page defends against framing with a client-side JavaScript "frame buster" (code that detects it's been iframed and breaks out), rather than a real HTTP-level defense — which only works if the framed page is allowed to execute JavaScript at all.

**Steps:**
1. Logged in as `wiener` on this lab's own instance and located the "Update email" form on `/my-account`, which also accepts a prefilled value via an `email` URL query parameter.
2. Built the same invisible-iframe-plus-decoy-div overlay as Lab 9, but this time added a `sandbox="allow-forms"` attribute to the iframe — a sandboxed frame without `allow-scripts` cannot execute *any* JavaScript, including the page's own frame-busting code, while `allow-forms` still lets the "Update email" form actually submit.
3. Set the iframe's `src` to `/my-account?email=hacker@attacker-website.com`, so the email field would already contain the attacker's address before the victim ever "clicks".
4. Re-verified pixel alignment the same semi-transparent-overlay way as Lab 9 (the "Update email" button sits at a different Y offset than "Delete account", a few tiers higher up the page) and delivered the exploit to the victim — the victim's email was silently changed to the attacker's address, solving the lab.

**Takeaway:** A frame buster is a JavaScript-only defense, and `sandbox="allow-forms"` (deliberately omitting `allow-scripts`) neutralizes it completely while still allowing the exact form interaction the attack needs — client-side anti-framing code can never be a substitute for the real `X-Frame-Options`/CSP HTTP header defense.

---

## A note on tooling

All 8 JWT labs were solved entirely via `curl` and local Python (`PyJWT`, `cryptography`, and — for Lab 8's public-key derivation — `gmpy2` for fast arbitrary-precision arithmetic) with no browser interaction beyond launching each lab instance, continuing the pattern from [Day 7](day7-ssrf-and-path-traversal.md) and [Day 8](day8-xxe-and-os-command-injection.md) of preferring direct HTTP requests over the UI wherever a lab doesn't require a real browser context. The 2 Clickjacking labs, by contrast, inherently require a real browser (the exploit only exists as a rendered iframe overlay) — the main lesson there was that pixel alignment measured in a full-width browser tab doesn't transfer directly to how the same page renders inside a narrower iframe, and the fix was to temporarily raise the iframe's opacity and directly screenshot the overlap before committing to "deliver to victim," rather than guessing coordinates blind.
