# PortSwigger Web Security Academy — Prototype Pollution (Day 10)

My notes and write-ups from Day 10 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), **SSRF & Path Traversal** on [Day 7](day7-ssrf-and-path-traversal.md), **XXE Injection & OS Command Injection** on [Day 8](day8-xxe-and-os-command-injection.md), and **File Upload Vulnerabilities & Information Disclosure** on [Day 9](day9-file-upload-and-information-disclosure.md), today's topic is **Prototype Pollution** — 9 of the 10 labs in the topic (one Expert-level lab requires the public Burp Collaborator server, which isn't available in this setup, so it's skipped, same as one lab on [Day 6](day6-csrf.md)).

## What is prototype pollution?

Prototype pollution is a JavaScript-specific vulnerability class where an attacker manages to add arbitrary properties to `Object.prototype` — the base object that (almost) every other object in a JavaScript runtime inherits from. It usually arises when code recursively merges a user-controlled object (from a query string, a JSON body, or a web message) into an existing object without sanitizing keys like `__proto__` or `constructor.prototype`. On its own, polluting the prototype does nothing observable; the real impact comes from finding a **gadget** — existing application or library code that reads a property which was never explicitly set, and does something dangerous with it (renders it into the DOM, passes it to `eval()`, uses it to configure a spawned child process, etc). On the client this typically leads to DOM XSS; on the server, in Node.js apps, it can escalate all the way to remote code execution.

## Lab 1: DOM XSS via client-side prototype pollution
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-client-side-prototype-pollution

**Vulnerability:** A source in `location.search` merges attacker-controlled query parameters into `Object.prototype`, and `searchLogger.js` reads a `transport_url` property off a `config` object — a property that's never defined by default — to dynamically append a `<script src="...">` tag to the page.

**Steps:**
1. Confirmed the pollution source by requesting `/?__proto__[foo]=bar` and checking `Object.prototype.foo` in the console.
2. Read the site's JavaScript and found `searchLogger.js` building a `<script>` tag from `config.transport_url`, which is normally `undefined`.
3. Requested `/?__proto__[transport_url]=data:,alert(1);` — the polluted `transport_url` became the injected script's `src`, and the browser fetched and executed the `data:` URL, calling `alert(1)`.

**Takeaway:** An "unused" config property with no default value is a prototype pollution gadget waiting to happen — as soon as anything reads it without an existence check, an attacker who can pollute the prototype controls its value.

---

## Lab 2: DOM XSS via an alternative prototype pollution vector
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-dom-xss-via-an-alternative-prototype-pollution-vector

**Vulnerability:** The bracket-notation source (`__proto__[foo]=bar`) doesn't work here, but the dot-notation form does. The gadget this time is a genuine `eval()` sink in `searchLoggerAlternative.js` that evaluates a `manager.sequence` property.

**Steps:**
1. Found that `/?__proto__[foo]=bar` left `Object.prototype` unmodified, but `/?__proto__.foo=bar` did pollute it — a different parser handles dot-notation keys differently from bracket notation.
2. Located the `eval()` call on `manager.sequence` in `searchLoggerAlternative.js`.
3. Injected `/?__proto__.sequence=alert(1)` — the payload reached `eval()` but the console showed a syntax error: the app appends a numeric `1` after the injected value, turning `alert(1)` into invalid syntax `alert(1)1`.
4. Fixed the syntax by appending a trailing minus sign: `/?__proto__.sequence=alert(1)-`, which turns the append into a harmless subtraction (`alert(1)-1`) that's still valid JavaScript. This called `alert(1)` and solved the lab.

**Takeaway:** Different property-assignment code paths can have different quirks around `__proto__` — if one prototype pollution vector fails, it's worth testing dot notation vs. bracket notation before concluding the app isn't vulnerable. Also, a sink that appends fixed text after your payload just means the payload needs to end in something that keeps the surrounding code syntactically valid.

---

## Lab 3: Client-side prototype pollution via flawed sanitization
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-via-flawed-sanitization

**Vulnerability:** The app strips the literal string `__proto__` from keys before merging — but only once, not recursively, so a key crafted to still contain `__proto__` *after* one round of stripping survives.

**Steps:**
1. Confirmed both `__proto__[foo]=bar` and `__proto__.foo=bar` were neutralized by the site's `sanitizeKey()` filter.
2. Built a key that becomes `__proto__` once the substring `__proto__` is removed from its middle: `__pro__proto__to__`. Stripping the inner `__proto__` once collapses it to exactly `__proto__`.
3. Used the same `transport_url` gadget from Lab 1: `/?__pro__proto__to__[transport_url]=data:,alert(1);` — the sanitizer stripped the embedded `__proto__`, leaving a clean `__proto__[transport_url]` key, and the payload executed.

**Takeaway:** A denylist filter that removes a dangerous substring only once (instead of looping until no more matches are found) can always be defeated by nesting the substring inside itself — the same class of bug as the double-URL-decode path traversal bypass from [Day 7](day7-ssrf-and-path-traversal.md#lab-4-file-path-traversal-traversal-sequences-stripped-with-superfluous-url-decode).

---

## Lab 4: Client-side prototype pollution in third-party libraries
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/client-side/lab-prototype-pollution-client-side-prototype-pollution-in-third-party-libraries

**Vulnerability:** A gadget lives inside a minified third-party library rather than the site's own code: a `hitCallback` property, once polluted, is passed straight into `setTimeout()`, giving arbitrary code execution. PortSwigger's own solution recommends discovering this specific gadget with the DOM Invader Burp extension, since it's easy to miss by hand in minified code — I used the documented gadget directly instead. The lab is solved by delivering the payload to a simulated victim via the built-in exploit server rather than triggering it in my own browser.

**Steps:**
1. Confirmed the pollution source lives in the URL fragment (`#__proto__[...]`).
2. Used the known `hitCallback` → `setTimeout()` gadget documented by PortSwigger Research for this class of vulnerability.
3. On the lab's exploit server, set the response body to a script that redirects the victim to `https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert%28document.cookie%29`.
4. Delivered the exploit to the victim directly (skipping the "test on yourself" step, since triggering `alert()` in my own automated browser tab freezes it — see the tooling note below). The victim's simulated browser loaded the URL, `setTimeout()` invoked the polluted `hitCallback`, and `alert(document.cookie)` fired in their session, solving the lab.

**Takeaway:** Prototype pollution gadgets aren't limited to first-party code — any imported library that calls a dangerous sink using an object property without checking it's actually its own (`hasOwnProperty`) can be a gadget, and these are especially easy to miss in minified/bundled dependencies.

---

## Lab 5: Client-side prototype pollution via browser APIs
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/client-side/browser-apis/lab-prototype-pollution-client-side-prototype-pollution-via-browser-apis

**Vulnerability:** The developers noticed the `transport_url` gadget from Lab 1 and tried to lock it down with `Object.defineProperty(config, 'transport_url', {writable:false, configurable:false})` — but that call itself accepts a descriptor object, and the descriptor never sets an explicit `value`. A polluted `value` property on the prototype is inherited by the descriptor object and used as the property's value.

**Steps:**
1. Confirmed `/?__proto__[foo]=bar` pollutes `Object.prototype` normally (no sanitization this time).
2. Read the source and found the site now "locks" `transport_url` via `Object.defineProperty` right after setting it — but with no `value` key in the descriptor object passed in.
3. Injected `/?__proto__[value]=data:,alert(1);` — the descriptor's missing `value` was inherited from the polluted prototype, so `Object.defineProperty` set `config.transport_url` to the malicious `data:` URL anyway, and the `<script>` gadget from Lab 1 fired the same way.

**Takeaway:** Freezing a property against further writes doesn't help if the *initial* write is itself driven by an incomplete, prototype-inheriting descriptor object — a well-intentioned defense against one gadget opened up a subtly different one, based on real-world research into `Object.defineProperty()` and `fetch()` as prototype pollution gadgets.

---

## Lab 6: Privilege escalation via server-side prototype pollution
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-privilege-escalation-via-server-side-prototype-pollution

**Vulnerability:** A Node.js/Express backend merges the JSON body of a "change address" request into a server-side user object without sanitizing keys, so a `__proto__` key in the request pollutes `Object.prototype` for the whole process, and any user object that doesn't explicitly define its own `isAdmin` property inherits whatever value was polluted there.

**Steps:**
1. Logged in as `wiener:peter` (the login and address-update endpoints on this app both require `Content-Type: application/json` rather than form-encoding, and the address form also submits a hidden `sessionId` field alongside the visible address fields).
2. Sent `POST /my-account/change-address` with `"__proto__": {"foo": "bar"}` added to the JSON body and saw `foo` reflected in the response — confirming the pollution source.
3. Noticed the response also included an `isAdmin: false` field, and repeated the request with `"__proto__": {"isAdmin": true}` instead — the response came back with `isAdmin: true`.
4. Reloaded `/admin`, which was now accessible, and requested `/admin/delete?username=carlos` to delete the user and solve the lab.

**Takeaway:** Once a source lets you add arbitrary properties to `Object.prototype`, any response field whose value looks unexpectedly attacker-influenced (here, an `isAdmin` flag on a plain address-update response) is worth testing directly as a gadget — the entire attack was three raw `curl` requests, no browser interaction needed.

---

## Lab 7: Detecting server-side prototype pollution without polluted property reflection
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-detecting-server-side-prototype-pollution-without-polluted-property-reflection

**Vulnerability:** Same unsanitized merge as Lab 6, but this lab is about *detecting* the pollution non-destructively when the injected property isn't reflected anywhere in a normal response — using the "status code override" technique, where Express's error handler reads a polluted `status`/`statusCode` property off `Object.prototype` whenever it builds an error response.

**Steps:**
1. Logged in and confirmed that polluting `__proto__.foo` had no visible effect on the normal `change-address` response — no reflection this time.
2. Sent a request with deliberately broken JSON syntax (a missing comma) and observed a `500` response whose JSON error body contained `"status": 400` — proof that Express's internal error object has a `status` property that ends up in the response.
3. Sent a valid request that polluted `__proto__.status` to an arbitrary, distinctive value (`555`) and confirmed the app still behaved normally (`200`, unaffected).
4. Broke the JSON syntax again while the `status: 555` pollution was still active — the error response this time came back with `"statusCode": 555, "status": 555`, matching the injected value instead of the framework's own default. This confirmed the pollution was live even though nothing was ever reflected directly.

**Takeaway:** When an injected property isn't reflected anywhere, forcing the app into a code path that reads a common, framework-level property (like an HTTP status code, a JSON indentation width, or a response charset) off the prototype is a reliable, non-destructive way to confirm prototype pollution before looking for an exploitable gadget.

---

## Lab 8: Bypassing flawed input filters for server-side prototype pollution
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-bypassing-flawed-input-filters-for-server-side-prototype-pollution

**Vulnerability:** The same address-update endpoint as Lab 6, but this time the server strips any top-level `__proto__` key from the request body before merging — the merge logic itself, however, still honors the alternative `constructor.prototype` path to the same global prototype object.

**Steps:**
1. Confirmed `"__proto__": {"isAdmin": true}` no longer worked — the key was filtered out server-side before the merge.
2. Switched to the `constructor`/`prototype` vector: `"constructor": {"prototype": {"isAdmin": true}}`. This isn't a denylisted key, but `object.constructor.prototype` is the same object as `object.__proto__` for ordinary objects created via the `Object` constructor.
3. Sent the address-update request with that payload; the response came back with `isAdmin: true`, confirming the prototype was polluted despite the filter.
4. Reloaded `/admin` and deleted `carlos` to solve the lab, exactly as in Lab 6.

**Takeaway:** Blocklisting the literal string `__proto__` only closes one of at least two standard routes to the same prototype object — `constructor.prototype` reaches it too, and any merge function that doesn't also guard against `constructor`/`prototype` keys is still fully exploitable.

---

## Lab 9: Remote code execution via server-side prototype pollution
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/prototype-pollution/server-side/lab-remote-code-execution-via-server-side-prototype-pollution

**Vulnerability:** Same unsanitized `__proto__` merge on the address-update endpoint as Lab 6, but this app also has an admin "run maintenance jobs" feature that spawns Node.js child processes. Node's `child_process` functions read an `execArgv` option that gets passed straight to the new Node process — and if that option is inherited from a polluted prototype instead of set explicitly, an attacker can smuggle in a `--eval` argument that runs arbitrary JavaScript (and, from there, arbitrary shell commands) in the spawned process.

**Steps:**
1. Logged in as `wiener` (this lab starts with `isAdmin` already true, so the admin panel and its maintenance-jobs feature were accessible immediately).
2. Polluted the prototype via the address-update endpoint with `"__proto__": {"execArgv": ["--eval=require('child_process').execSync('rm /home/carlos/morale.txt')"]}`.
3. `POST`ed to `/admin/jobs` with the maintenance tasks (`db-cleanup`, `fs-cleanup`) and the page's CSRF token and session ID. The response showed `db-cleanup` succeeding and `fs-cleanup` failing — exactly the symptom PortSwigger's own solution describes, since the injected `--eval` argument hijacked the spawned child process instead of letting it run its normal job.
4. The injected `rm` command had already executed as a side effect of spawning the polluted child process, deleting `/home/carlos/morale.txt` and solving the lab — all without needing Burp Collaborator, which the official walkthrough only uses for an optional interim verification step.

**Takeaway:** In Node.js, `execArgv` (and similar low-level options passed to `child_process.spawn`/`fork`) are exactly the kind of "internal" configuration property that developers never expect a user to control — but if it's read off an object without an explicit own-property check, prototype pollution turns any code path that spawns a child process into remote code execution.

---

## A note on tooling

Most of the client-side labs required at least one call to `alert()` to prove DOM XSS, which pops a real native browser dialog that blocks the automated browser tab until dismissed — a known limitation of driving Chrome through the extension used to solve these labs. The workaround: since PortSwigger's grading registers the solve as soon as `alert()` is called (independent of whether the resulting dialog has been dismissed yet), I opened a second tab after firing the payload and re-checked the lab's "Solved" status there, then closed the stuck tab, instead of waiting on it. The one skipped lab, **Exfiltrating sensitive data via server-side prototype pollution** (Expert), explicitly requires exfiltrating data to the *public Burp Collaborator server* for its solved-check — with no Burp Suite client available in this setup, there's no way to generate or poll a Collaborator payload, so it was skipped, matching prior skips of Collaborator-only labs on [Day 6](day6-csrf.md) and [Day 7](day7-ssrf-and-path-traversal.md). All four server-side labs were solved entirely with `curl` — no browser interaction needed beyond launching each lab instance.
