# PortSwigger Web Security Academy — Business Logic Vulnerabilities (Day 5)

My notes and write-ups from Day 5 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), and **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), today's topic was **Business Logic Vulnerabilities** — 10 labs (5 Apprentice/quick-Practitioner, 5 deeper Practitioner).

## What are business logic vulnerabilities?

These flaws aren't about broken syntax or missing sanitization — the app parses and validates input perfectly fine, but its *rules* are wrong or incomplete. Every lab below exploited a mismatch between what the developers assumed a user would do and what the application actually let them do: trusting a client-side price, forgetting that "add to cart" accepts negative quantities, applying a coupon code more than once, integer overflow in a price calculation, truncating a string in a way that changes its meaning, reusing one endpoint for two different trust levels, skipping a step in a multi-page checkout, skipping a step in a multi-page login, and a discount/refund loop that mints money instead of just moving it around. None of these are "hacking" in the traditional sense — they're closer to finding a rules loophole in a board game.

---

## Lab 1: Excessive trust in client-side controls
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls

**Vulnerability:** The "Add to cart" form for a product includes the price as a *hidden* form field, and the server trusts whatever value comes back in that field instead of looking up the real price itself.

**Steps:**
1. Opened the $1337 leather jacket's product page and found the add-to-cart form, whose hidden `price` field held `133700` (cents).
2. Edited that hidden field's value to `1` via the console before submitting, then added the item to the cart.
3. The cart showed the jacket at $0.01 — well within the $100 store credit — so I placed the order.

**Takeaway:** Anything sent to the browser is attacker-controlled the moment it round-trips back to the server. A price, a role, a quantity limit — if the server doesn't re-derive or re-validate it server-side, it isn't really enforced at all.

---

## Lab 2: High-level logic vulnerability
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-high-level

**Vulnerability:** Unlike Lab 1, this store computes the price server-side from quantity × unit price — but it never rejects a *negative* quantity, so a "purchase" of a cheap item can be turned into a negative-cost line that offsets the price of something else in the same order.

**Steps:**
1. Added the $1337 jacket to the cart with quantity 1 (a straight `-1` quantity on the jacket itself just triggered a "cart total cannot be negative" error).
2. Added "The Giant Enter Key" ($48.23) with quantity **-26** in a second cart line, bringing the order total to $1337.00 − $1253.98 = **$83.02** — comfortably under the $100 credit.
3. Placed the order; the confirmation still listed the jacket at quantity 1, so the lab counted it as bought.

**Takeaway:** Validating "no negative total" isn't the same as validating "no negative *inputs*." A negative quantity on an unrelated item is a legitimate way to smuggle a discount past a total-only check.

---

## Lab 3: Inconsistent security controls
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-security-controls

**Vulnerability:** The app grants admin-panel access to any account whose email ends in `@dontwannacry.com` (the "company" domain). That check runs against whatever email is *currently* on the account — but only the very first registration email needs to pass a real ownership check (click the confirmation link); a later "change email" doesn't require re-confirming.

**Steps:**
1. Registered normally with `attacker2@<my-exploit-server-domain>`, then clicked the confirmation link from the lab's built-in email client to activate the account.
2. Logged in, went to "My account," and changed the email address to `attacker2@dontwannacry.com` — no confirmation was required for this change.
3. Visited `/admin` — now recognized as a DontWannaCry employee — and deleted `carlos`.

**Takeaway:** Trust established once (an email ownership check) doesn't automatically stay valid if the underlying value can be changed later without re-verification. Every place that *reads* a trust signal needs to agree with every place that can *write* it.

---

## Lab 4: Flawed enforcement of business rules
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-flawed-enforcement-of-business-rules

**Vulnerability:** Two coupon codes (`NEWCUST5`, a flat $5 off, and `SIGNUP30`, a flat 30%-of-original off) each individually check "have I already been applied?" — but that check only looks at the *immediately preceding* application, not the whole order history, so alternating between the two codes bypasses the "one use" rule entirely.

**Steps:**
1. Signed up for the newsletter to unlock `SIGNUP30`, and noted the site already advertised `NEWCUST5`.
2. Added the $1337 jacket to the cart, then applied `SIGNUP30`, `NEWCUST5`, `SIGNUP30`, `NEWCUST5`... alternating 14 times total.
3. Each `SIGNUP30` re-application knocked off another flat $401.10, and each `NEWCUST5` knocked off another flat $5 — after 14 applications the total was reduced from $1337.00 to **$0.00**.
4. Placed the order.

**Takeaway:** "You can't apply the same coupon twice in a row" is a much weaker rule than "you can't apply a coupon more than once." Any de-duplication check that only compares against the last action, rather than the full history, can be defeated by interleaving.

---

## Lab 5: Low-level logic flaw
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-low-level

**Vulnerability:** The server-side cart total is stored as a 32-bit signed integer (cents). The per-request quantity is capped at 0–99, but repeated "add to cart" calls accumulate onto the same line indefinitely, so the running total can be pushed past `2,147,483,647` and wrap around to a negative number, then wrap again on the way back up.

**Steps:**
1. Worked out that the jacket costs 133700 cents per unit, and that `133700 × 2^32` has a greatest common factor of 4, meaning every multiple-of-4 cent value in the wraparound cycle is reachable for some integer quantity. Solved the modular equation for the smallest quantity `Q` where `(Q × 133700) mod 2^32` lands between $0 and $100: **Q = 385,487**.
2. Since each individual "add to cart" request is capped at quantity 99, scripted repeated POST requests (batched with moderate concurrency) against `/cart` to accumulate the jacket's quantity up to exactly 385,487 units.
3. The cart total had overflowed the 32-bit boundary and wrapped back around to **$43.48** — well inside the $100 credit — so I placed the order for 385,487 jackets.

**Takeaway:** Any server-side arithmetic on attacker-influenced quantities needs overflow checks, not just per-request range checks. Capping a single request to "0–99" does nothing if the *accumulated* value has no upper bound.

---

## Lab 6: Inconsistent handling of exceptional input
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-inconsistent-handling-of-exceptional-input

**Vulnerability:** The registration email gets validated (and its confirmation link *sent*) against the value the user actually typed, but the application server truncates the value it *stores* on the account to 255 characters. If the real `@dontwannacry.com` suffix falls entirely within those first 255 characters and everything after it (my real, attacker-controlled mail domain) is what gets truncated away, the stored value looks like a fully legitimate company address.

**Steps:**
1. Computed a padding string of exactly the right length so that `<234 filler chars>@dontwannacry.com.<my-exploit-server-domain>` has its 255th character land exactly on the final `m` of `dontwannacry.com`.
2. Registered with that address, then opened the lab's email client and clicked the confirmation link — the *full* email (all 315 characters) was what the confirmation was actually sent to and validated against.
3. Logged in and checked "My account": the stored email had been silently truncated to the first 255 characters, i.e. `...@dontwannacry.com` with nothing after it — a seemingly valid company address.
4. This satisfied the admin-panel's domain check (same logic as Lab 3); visited `/admin` and deleted `carlos`.

**Takeaway:** When two different parts of a system apply *different* length limits (or different parsing rules) to the same input, the gap between them is exploitable — the confirmation step trusted the full string, but the authorization check only ever saw the truncated one.

---

## Lab 7: Weak isolation on dual-use endpoint
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-weak-isolation-on-dual-use-endpoint

**Vulnerability:** The "change password" form includes an editable `username` field (presumably reused from an admin-side "reset another user's password" feature) and doesn't actually verify that `current-password` matches the *target* user before applying the change — it just checks that some current password was supplied at all.

**Steps:**
1. Logged in as `wiener` and inspected the change-password form: it posts `csrf`, `username` (pre-filled with `wiener`, but not read-only), `current-password`, and two new-password fields to `/my-account/change-password`.
2. Submitted a request with `username=administrator`, a new password of my choosing, and no `current-password` at all — the server accepted it and reported "Password changed successfully!"
3. Logged out, logged back in as `administrator` with the new password, opened the admin panel, and deleted `carlos`.

**Takeaway:** A form field that lets you name an *arbitrary* target user is only safe if every code path that consumes it re-checks authorization for that specific target — reusing the same endpoint for "change my own password" and "reset someone else's password" without that check collapses two very different trust levels into one.

---

## Lab 8: Insufficient workflow validation
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation

**Vulnerability:** The checkout flow is `POST /cart/checkout` (which correctly rejects the order if store credit is insufficient) followed by a separate `GET /cart/order-confirmation?order-confirmed=true` that actually finalizes and displays the order — but that second step never re-checks whether the first one actually succeeded.

**Steps:**
1. Logged in, added the $1337 jacket to the cart (store credit was only $100), and confirmed that clicking "Place order" correctly failed with "Not enough store credit for this purchase."
2. With the (still unpaid) jacket sitting in the cart, navigated directly to `GET /cart/order-confirmation?order-confirmed=true`, skipping the checkout POST entirely.
3. The page rendered "Your order is on its way!" for the full-price jacket, and store credit remained untouched at $100 — the order was finalized without ever passing the funds check.

**Takeaway:** In a multi-step process, every step needs to independently verify that the *required prior state* actually exists — a confirmation page that just trusts "the user must have gotten here legitimately" can be reached directly, skipping whatever validation the developer assumed happened first.

---

## Lab 9: Authentication bypass via flawed state machine
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-authentication-bypass-via-flawed-state-machine

**Vulnerability:** After a successful `POST /login`, the server redirects the browser to `GET /role-selector` where the user picks which role to act as for the session — but until that request is made, the session's role has already *defaulted* to `administrator` rather than being left unset.

**Steps:**
1. Submitted the login form via a scripted `fetch()` with `redirect: 'manual'`, so the browser received (and stored) the session cookie from the successful login but did **not** automatically follow the redirect to `/role-selector`.
2. Navigated straight to `/admin` instead of ever visiting the role-selection page.
3. The session's role had never been downgraded from its administrator default, so the admin panel loaded normally; deleted `carlos`.

**Takeaway:** A "safe by default" state should mean the *most* restrictive option, not the most privileged one. If an intermediate step is what's supposed to lower your privilege level, an attacker who can simply skip that request keeps whatever the state machine's starting point was.

---

## Lab 10: Infinite money logic flaw
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-infinite-money

**Vulnerability:** A $10 gift card can be bought at a 30% discount using the `SIGNUP30` newsletter coupon (costing only $7), and then redeemed on the account page for the full $10 of store credit — netting a flat $3 profit every time the buy-then-redeem cycle is repeated, with no cap on repetitions.

**Steps:**
1. Signed up for the newsletter to get `SIGNUP30`, then manually ran the cycle once (add gift card to cart → apply coupon → checkout → copy the generated gift card code from the confirmation page → redeem it on "My account") to confirm store credit went up by $3 net.
2. Scripted the exact same five-request sequence (`POST /cart`, `GET /cart` for a fresh CSRF token, `POST /cart/coupon`, `POST /cart/checkout`, then `POST /gift-card` with the code pulled straight out of the checkout response) and ran it in a loop.
3. Ran several such loops concurrently to speed things up, polling store credit periodically: $100 → $313 → $667 → $1033 → **$1342** after roughly 470 total cycles.
4. With store credit comfortably over $1337, bought the leather jacket outright to solve the lab.

**Takeaway:** Any "buy X, get Y back" flow where Y is worth more than X's actual discounted cost is a money-printing loop — the fix isn't to limit *how* the gift card is bought or redeemed individually, but to make sure the redemption value can never exceed what was actually paid for it. This is also a good example of how a purely mechanical exploit (no creativity needed after the first cycle) can be trivially automated once you understand the request sequence.

---

## A note on scripting these

Labs 5 and 10 both came down to "the underlying flaw is simple, but exploiting it to completion requires hundreds of nearly-identical requests" — an integer overflow needing a very specific quantity, and a profit loop needing to run until the balance crosses a threshold. Both were solved by reproducing the *manual* request sequence once to understand it, then automating that exact sequence via scripted `fetch()` calls rather than clicking through the UI hundreds of times. Worth remembering: PortSwigger's own official solutions for both of these use Burp Intruder in exactly the same "repeat this one request/sequence N times" way.
