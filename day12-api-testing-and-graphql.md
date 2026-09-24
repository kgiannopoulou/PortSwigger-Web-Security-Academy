# PortSwigger Web Security Academy — API Testing & GraphQL API Vulnerabilities (Day 12)

My notes and write-ups from Day 12 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), **SSRF & Path Traversal** on [Day 7](day7-ssrf-and-path-traversal.md), **XXE Injection & OS Command Injection** on [Day 8](day8-xxe-and-os-command-injection.md), **File Upload Vulnerabilities & Information Disclosure** on [Day 9](day9-file-upload-and-information-disclosure.md), **Prototype Pollution** on [Day 10](day10-prototype-pollution.md), and **JWT Attacks & Clickjacking** on [Day 11](day11-jwt-and-clickjacking.md), today's topic is **API Testing** — the full 5-lab topic, including both server-side parameter pollution labs — plus the full 5-lab **GraphQL API vulnerabilities** topic, for a 10-lab day on attacking APIs.

## What is API testing?

Modern web apps are built on APIs — RESTful and JSON endpoints that the front-end calls to read and change data. The security problem is that the front-end only ever exercises a small, well-behaved slice of what the API can actually do: extra endpoints, extra HTTP methods, extra object fields and internal-only parameters all still exist on the server, just unused by the UI. API testing is the practice of ignoring the front-end's happy path and interrogating the API directly — reading its documentation, changing HTTP methods, adding fields the UI never sends, and reading the error messages it gives back — to reach functionality and data the developers assumed nobody would ever touch. **Server-side parameter pollution** is a specialised case where user input is unsafely folded into a *second*, internal API request, letting an attacker inject their own parameters or path segments into that hidden request.

## What are GraphQL API vulnerabilities?

GraphQL is a query language for APIs where the client sends a single structured query (or `mutation`) to one endpoint and asks for exactly the fields it wants. Its power is also its weakness: the schema often exposes far more than the UI uses, `introspection` lets a client download the entire schema, a single request can contain many aliased operations at once, and the endpoint itself is frequently left discoverable and mis-configured. GraphQL attacks abuse these features — reading hidden fields and objects, discovering the endpoint and schema despite defences, batching operations to defeat rate limits, and (because some servers accept form-encoded GraphQL) mounting CSRF against mutations.

## Lab 1: Exploiting an API endpoint using documentation
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation

**Vulnerability:** The API serves its own interactive documentation from a discoverable path, and that documentation exposes a destructive endpoint the front-end never uses.

**Steps:**
1. Logged in as `wiener:peter` and noticed the account page's email-change request goes to `/api/user/wiener`, hinting at a REST API rooted at `/api`.
2. Requested `/api/` directly and got a live Swagger/OpenAPI documentation page listing every operation on `/api/user/{username}`, including a `DELETE` method.
3. Sent `DELETE /api/user/carlos` — the server replied `{"status":"User deleted"}` (`200`), deleting `carlos` and solving the lab.

**Takeaway:** API documentation is a gift to an attacker when it's reachable in production — it turns endpoint discovery into simply reading a menu. Documentation that must exist should be locked behind authentication, and destructive methods like `DELETE` should never be exposed to a normal user's token.

---

## Lab 2: Finding and exploiting an unused API endpoint
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint

**Vulnerability:** A price endpoint that the UI only ever reads (`GET`) also silently supports `PATCH`, letting a customer rewrite a product's price before buying it.

**Steps:**
1. Logged in as `wiener` and identified the "Lightweight l33t Leather Jacket" as product 1, priced `$1337.00`, whose price the UI fetches from `GET /api/products/1/price`.
2. Sent an `OPTIONS` request to that endpoint — the response's `Allow` header advertised `GET, PATCH`, revealing an unused write method.
3. Sent `PATCH /api/products/1/price` with `Content-Type: application/json` and body `{"price":0}` — the server accepted it and returned `{"price":"$0.00"}`.
4. Added the now-free jacket to the cart and checked out, landing on `/cart/order-confirmation?order-confirmed=true` and solving the lab.

**Takeaway:** An endpoint's exposed HTTP methods are part of its attack surface even when the front-end only uses one of them — `OPTIONS` (and simply *trying* other verbs) is the fastest way to find write access hiding behind a read-only-looking URL. Price should always be authoritative server-side, never mutable by the client.

---

## Lab 3: Exploiting a mass assignment vulnerability
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability

**Vulnerability:** The checkout API blindly binds the whole request JSON onto its internal order object, including a `chosen_discount` field the UI never sends — so a client can assign itself a discount.

**Steps:**
1. Logged in as `wiener`, added the jacket to the cart, and sent `GET /api/checkout` to see the order object the client is expected to submit.
2. The response included a hidden structure the UI never exposes: `{"chosen_discount":{"percentage":0},"chosen_products":[...]}` — a discount field, defaulting to `0`.
3. Sent `POST /api/checkout` with the same shape but `{"chosen_discount":{"percentage":100},"chosen_products":[{"product_id":"1","quantity":1}]}` — the server returned `201`, applied a 100% discount, and solved the lab.

**Takeaway:** Mass assignment happens when a framework auto-maps every field in the request body onto a server-side object; fields the UI never renders (`chosen_discount` here) are the ones worth probing, and a `GET` on the same resource often reveals their exact names. The fix is an explicit allowlist of client-settable fields.

---

## Lab 4: Exploiting server-side parameter pollution in a query string
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-query-string

**Vulnerability:** The password-reset feature drops the submitted username into an internal API query string as `...?username=<input>&field=email`, without encoding it — so injecting URL syntax lets an attacker add and override parameters on that internal request.

**Steps:**
1. Submitted the forgot-password form with `username=administrator` — it worked normally, and the internal API returned the (masked) email.
2. Probed with query syntax and read the error messages to map the internal request: `administrator%23` (a `#`) gave *"Field not specified."* (the `#` truncated the trailing `&field=...`); `administrator%26x=y` (an `&`) gave *"Parameter is not supported."*; and `administrator%26field=x` gave *"Invalid field."*
3. Enumerated valid `field` values by injecting `administrator%26field=<name>%23` — `email`, `username`, and crucially `reset_token` all returned data, while others were rejected.
4. Sent `username=administrator%26field=reset_token%23`, leaking the administrator's password-reset token in the response.
5. Used the token at `/forgot-password?reset_token=<token>` to set a new admin password, logged in as `administrator`, and deleted `carlos` from the admin panel to solve the lab.

**Takeaway:** Whenever user input is forwarded into a second, server-to-server request, treat that request as an injection surface just like SQL or HTML — `#`, `&` and `=` in the query string let you truncate, append and override the internal parameters. The verbose, differentiated error messages ("field not specified" vs "invalid field") are what make the internal API's shape recoverable one guess at a time.

---

## Lab 5: Exploiting server-side parameter pollution in a REST URL
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/api-testing/server-side-parameter-pollution/lab-exploiting-server-side-parameter-pollution-in-rest-url

**Vulnerability:** Same class of bug as Lab 4, but the username is spliced into an internal REST *URL path* (`/api/internal/v1/users/<input>/field/email`) rather than a query string — so path-traversal sequences let an attacker reach entirely different endpoints of the internal API.

**Steps:**
1. There's no `wiener` account here — the attack is unauthenticated via forgot-password. Submitting `administrator` returned the masked email; appending `%23` (a `#`) gave *"Invalid route. Please refer to the API definition"*, confirming the input lands in a path and hinting that API docs exist.
2. Traversed out of the users path to grab the definition: `username=../../../../openapi.json%23` returned (a truncated view of) the OpenAPI spec, revealing the internal template `/api/internal/v1/users/{username}/field/{field}`.
3. Confirmed I controlled the trailing field — `administrator/field/email%23` still returned the email — but the default path rejected `passwordResetToken`.
4. Adjusted the traversal to hit the reset-token endpoint on a different path prefix: `username=../../v1/users/administrator/field/passwordResetToken%23` returned `{"result": "9mpdh2aru68tf9mh9bac8dsa58h62qul"}`, the administrator's reset token.
5. Reset the admin password at `/forgot-password?passwordResetToken=<token>`, logged in as `administrator`, and deleted `carlos` to solve the lab.

**Takeaway:** When user input becomes a *path segment* in an internal REST URL, `../` traversal is the equivalent of parameter injection — it lets you pivot from the one endpoint the app intended (`/field/email`) to any other the internal API exposes. Reading the leaked OpenAPI definition first turns this from blind guessing into targeted requests; the real fix is to URL-encode and validate the segment, and to keep internal API definitions off the network entirely.

---

## Lab 6: Accessing private GraphQL posts
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts

**Vulnerability:** The blog's GraphQL query fetches a post by `id` and returns a `postPassword` field, and there's no authorization check preventing a client from requesting a post that isn't publicly listed.

**Steps:**
1. Read `/resources/js/gqlUtil.js`, which pointed the front-end at the GraphQL endpoint `/graphql/v1`, and `blogSummaryGql.js`, which uses `getAllBlogPosts`/`blogPost`. The public listing skips post `id 3`.
2. Sent a direct query for the missing post: `query{ getBlogPost(id:3){ id title postPassword } }`, which returned the hidden post "Awkward Breakups" and its `postPassword` (`82xhfooac1b78humj1kjz756ndoys0db`).
3. Submitted that password via the lab's `/submitSolution` endpoint (`{"correct":true}`) to solve the lab.

**Takeaway:** GraphQL will happily return any object you can name a valid `id` for — the fact that a post is missing from a public list is a UI decision, not an access control. Sensitive fields like `postPassword` should never be resolvable without an authorization check on the individual object.

---

## Lab 7: Accidental exposure of private GraphQL fields
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure

**Vulnerability:** The `User` type in the schema exposes a `password` field, and the `getUser` query returns it without authorization — so any user's credentials can be read straight out of the API.

**Steps:**
1. Ran introspection against `/graphql/v1` and saw a `getUser(id)` query. Introspecting the `User` type showed its fields: `id`, `username`, and `password`.
2. Queried `getUser(id:1){id username password}` and got `administrator` with password `z9que2ms58szvtnkd34o` (ids 2 and 3 returned `wiener` and `carlos`, confirming the whole user table was readable).
3. Since login here is a GraphQL `mutation` (the HTML form rejects `POST`), signed in with `mutation{login(input:{username:"administrator",password:"z9que2ms58szvtnkd34o"}){token success}}`, which set the session cookie.
4. Used that session to reach `/admin` and delete `carlos`, solving the lab. (The session cookie was scoped to `/graphql/`, so I sent it explicitly on the admin request — a browser drives the same flow through the UI.)

**Takeaway:** A schema is a contract that describes *everything* an API can return — leaving a `password` field on a publicly-queryable type exposes it regardless of what the front-end asks for. Introspection makes this trivial to find, which is exactly why credential fields must never live on a returnable type.

---

## Lab 8: Finding a hidden GraphQL endpoint
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint

**Vulnerability:** The GraphQL endpoint isn't linked anywhere and tries to block introspection, but the block is a naive string filter and the endpoint answers to `GET`, leaving both discoverable.

**Steps:**
1. Probed common paths with the universal query `{__typename}`. `POST` to `/api` returned `405 Method Not Allowed`, but a `GET` request — `GET /api?query={__typename}` — returned `{"data":{"__typename":"query"}}`, revealing the hidden endpoint.
2. A naive introspection query was rejected with *"GraphQL introspection is not allowed, but the query contained `__schema` or `__type`"* — the defence matches the literal `__schema{`.
3. Bypassed it by inserting a newline between `__schema` and its selection set (`query{__schema` ⏎ `{...}}`), which slips past the pattern while staying valid GraphQL. Full introspection revealed a `deleteOrganizationUser(input:{id:Int})` mutation and a `getUser(id)` query.
4. Confirmed `getUser(id:3)` was `carlos`, then ran the mutation `mutation{deleteOrganizationUser(input:{id:3}){user{id username}}}` via `GET` (since `POST` is blocked), deleting `carlos` and solving the lab.

**Takeaway:** "Security by not linking it" is no security at all — GraphQL endpoints sit on a short list of predictable paths and answer a universal probe query. And an introspection filter that matches `__schema{` is defeated by a single newline; the only real defence is to disable introspection properly in production.

---

## Lab 9: Bypassing GraphQL brute force protections
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass

**Vulnerability:** The login rate limiter counts *requests*, but GraphQL lets a single request contain many aliased copies of the same mutation — so hundreds of password guesses can ride in on one request that the limiter counts as one.

**Steps:**
1. Introspected the `login` mutation at `/graphql/v1`: it takes `LoginInput{username,password}` and returns `{token, success}`.
2. Took PortSwigger's [authentication lab password list](https://portswigger.net/web-security/authentication/auth-lab-passwords) (100 candidates) and built one mutation containing 100 aliased calls — `bf0: login(input:{username:"carlos",password:"123456"}){success token} bf1: ...` — one alias per password.
3. Sent that single request; the rate limiter never tripped because it was one HTTP request. Parsing the response for `success:true` pointed at alias `bf35`, i.e. password `jennifer`.
4. Logged in as `carlos:jennifer` (via the `login` mutation, which set the session) to solve the lab.

**Takeaway:** Aliases let one GraphQL request perform an operation arbitrarily many times, so any control that assumes "one attempt per request" — rate limits, lockouts, anti-automation — is trivially bypassed. Brute-force protection for GraphQL has to count *operations*, not requests.

---

## Lab 10: Performing CSRF exploits over GraphQL
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api

**Vulnerability:** The GraphQL endpoint accepts mutations sent as `application/x-www-form-urlencoded` and relies only on a `SameSite=None` session cookie for auth — no CSRF token — so an ordinary HTML form can drive a `changeEmail` mutation in a victim's session.

**Steps:**
1. Confirmed the vector: sending `changeEmail` as form-urlencoded (`Content-Type: application/x-www-form-urlencoded`, body `query=mutation{changeEmail(input:{email:"..."}){email}}`) to `/graphql/v1` is parsed and executed — and the session cookie is `SameSite=None`, so it rides along on cross-site requests.
2. Proved it end-to-end by logging in as `wiener`, replaying that exact form-encoded request with the session cookie, and watching the account email change to my test value.
3. Built an auto-submitting HTML form whose single hidden field is `query` set to `mutation{changeEmail(input:{email:"pwned@evil-attacker.net"}){email}}`, targeting the lab's `/graphql/v1`, and hosted it on the exploit server at `/exploit`.
4. Delivered it to the victim; their browser auto-submitted the form, changing the logged-in viewer's email and solving the lab.

**Takeaway:** Serving a GraphQL API over `x-www-form-urlencoded` throws away GraphQL's one accidental CSRF defence (that JSON requests can't be sent by a plain HTML form), and a `SameSite=None` cookie with no CSRF token does the rest. Mutations should require `application/json` (or a CSRF token) and the session cookie should be `SameSite=Lax` at minimum.

---

## A note on tooling

All 5 API-testing labs and the first 4 GraphQL labs were solved with `curl` plus small Python helpers — logging in with a cookie jar, reading OpenAPI definitions and error messages, scripting the SSPP path-traversal enumeration, running GraphQL introspection, generating Lab 9's 100-alias batched mutation and parsing the winning alias out of the response — continuing the direct-HTTP approach from the [JWT labs on Day 11](day11-jwt-and-clickjacking.md). Lab 5's public-facing `openapi.json` was length-truncated in the error wrapper, so the exact reset-token field/path took a couple of iterations to pin down. Lab 10 was the one that genuinely needed a browser: the GraphQL CSRF vector itself is scriptable and I verified it with `curl`, but the exploit server's "Deliver to victim" only fired reliably when clicked through the exploit-server UI rather than posted with `curl`, so the delivery step ran in the browser.
