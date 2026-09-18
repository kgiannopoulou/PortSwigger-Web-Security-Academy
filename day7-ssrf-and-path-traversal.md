# PortSwigger Web Security Academy — SSRF & Path Traversal (Day 7)

My notes and write-ups from Day 7 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), and **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), today's run covers two topics: **Server-Side Request Forgery (SSRF)** (4 labs) and **Path Traversal** (6 labs), for 10 labs total.

## What is SSRF?

Server-side request forgery is a vulnerability that lets an attacker make the *server* issue HTTP requests to a location the attacker chose, rather than the location the application intended. The server acts as a confused proxy: it fetches a URL on the attacker's behalf using its own network position, which often has access to internal systems (loopback interfaces, private IP ranges, internal admin panels) that are completely unreachable from the public internet. The labs below all revolve around the same "check stock" feature — a form that lets the front end ask a back-end service whether an item is in stock via a `stockApi` parameter containing a URL — and each one adds a different defense that turns out to be bypassable.

## What is path traversal?

Path traversal (a.k.a. directory traversal) lets an attacker read files outside a web application's intended root directory, typically by manipulating a filename parameter with sequences like `../` to walk up the directory tree. The labs below all revolve around an `/image?filename=` endpoint that's supposed to only ever serve product images, and each one adds a different sanitization attempt that turns out to be bypassable.

---

# Part 1: Server-Side Request Forgery (SSRF)

## Lab 1: Basic SSRF against the local server
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

**Vulnerability:** The stock-check feature POSTs a `stockApi` parameter containing a full URL to `/product/stock`, and the server fetches whatever URL it's given with no restriction at all.

**Steps:**
1. Found the stock-check form on a product page; its default `stockApi` value pointed at an external `stock.weliketoshop.net` URL.
2. Sent a POST to `/product/stock` with `stockApi=http://localhost/admin` — the server fetched its own `/admin` page and returned the HTML, revealing an admin panel with delete links for `wiener` and `carlos` (normally inaccessible without authentication, but trusted automatically when the request appears to come from the local machine).
3. Resent the request with `stockApi=http://localhost/admin/delete?username=carlos` to trigger the delete action and solve the lab.

**Takeaway:** Applications frequently grant implicit trust to requests that appear to originate from `localhost` (for disaster-recovery admin access, or because an access-control check lives in a separate front-end component that a loopback request bypasses). SSRF turns that implicit trust into a full authentication bypass.

---

## Lab 2: Basic SSRF against another back-end system
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

**Vulnerability:** Same stock-check SSRF, but this time the admin interface lives on a different internal host in the `192.168.0.0/24` private range rather than on the app server itself.

**Steps:**
1. Scripted a loop trying `stockApi=http://192.168.0.{1..255}:8080/admin` and checking for a `200` response, since the target's exact internal IP isn't given up front.
2. Found the admin interface at `192.168.0.128:8080/admin`, which listed `wiener` and `carlos` with delete links.
3. Resent the request with `stockApi=http://192.168.0.128:8080/admin/delete?username=carlos` to delete the user and solve the lab.

**Takeaway:** Internal back-end systems are often left completely unauthenticated because network topology (private IP ranges, no public route) is treated as the only access control needed. SSRF removes that assumption entirely — a simple internal port/IP sweep from the vulnerable server is enough to find them.

---

## Lab 3: SSRF with blacklist-based input filter
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter

**Vulnerability:** The server blocks obvious SSRF payloads via a blacklist — string matches on `localhost`/`127.0.0.1` for the host, and on `admin` for the path — rather than an allowlist.

**Steps:**
1. Confirmed `stockApi=http://localhost/admin` was blocked ("External stock check blocked for security reasons"), and that even alternate loopback representations (`127.1`, decimal `2130706433`, octal, `127.0.0.1.nip.io`, etc.) were also blocked — ruling out a naive host check.
2. Isolated that the block was actually two separate checks — one on the host string, one on the path string containing `admin` — by testing `http://external-domain/admin` (blocked) versus `http://external-domain/` (not blocked) versus `http://127.0.0.1/` (blocked). This showed `127.0.0.1`/`localhost` specifically (not the whole loopback range) were denylisted for the host, while `admin` anywhere in the path was denylisted separately.
3. Bypassed the host check with the alternate loopback shorthand `127.1` (not literally the string `127.0.0.1` or `localhost`, so it isn't caught by an exact-string blacklist), and bypassed the path check with case variation: `/Admin` instead of `/admin`.
4. Sent `stockApi=http://127.1/Admin/delete?username=carlos` to solve the lab.

**Takeaway:** Blacklists defend against the *exact strings* the developer thought of, not the underlying concept. Loopback addresses have many equivalent representations, and a path check that's case-sensitive is trivially dodged since most web servers route paths case-insensitively.

---

## Lab 4: SSRF with filter bypass via open redirection vulnerability
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection

**Vulnerability:** This app only accepts a *relative path* for `stockApi` (any absolute URL, even to the legitimate stock-check domain, is rejected outright as invalid) — but the app also has an open-redirect endpoint, `/product/nextProduct?currentProductId=X&path=<url>`, and the server-side HTTP client used to fetch the stock data follows redirects.

**Steps:**
1. Confirmed the default relative-path value (`/product/stock/check?productId=1&storeId=1`) worked, while any absolute URL — even to the app's own domain — was rejected as an "Invalid URL", meaning the filter here requires a bare relative path rather than checking a domain allowlist.
2. Found the lab's stated target, `http://192.168.0.12:8080/admin`, and chained it through the open redirect: `stockApi=/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin`. Since this value is still a relative path, it passed the filter; the server then requested it, hit the 302 redirect, and followed it straight to the internal admin panel.
3. Repeated with `path=http://192.168.0.12:8080/admin/delete?username=carlos` to delete the user and solve the lab.

**Takeaway:** Restricting SSRF input to "just a relative path, no external URLs" only protects the *first hop*. If the server-side HTTP client follows redirects (most do, by default), any on-site open-redirect gadget becomes a stepping stone to an arbitrary target — the filter never sees the real destination.

---

## Labs not attempted today

Three labs in this topic were left out of today's run:

- **SSRF with whitelist-based input filter** (Expert) — the filter does a strict, RFC-correct hostname equality check (confirmed via Java `URISyntaxException` messages leaking through on malformed input), which resisted all the standard bypasses (`user@host` credentials trick, `#` fragment trick, backslash-authority trick, subdomain-hierarchy trick, Unicode full-width `@`/`#` normalization tricks, chaining through the allowed domain's own open-redirect). Real progress was made ruling out a long list of techniques, but the working bypass wasn't found in a reasonable amount of time, so — per the "keep it moving" approach from [Day 5](day5-business-logic-vulnerabilities.md)/[Day 6](day6-csrf.md) — it was set aside rather than ground on indefinitely.
- **Blind SSRF with out-of-band detection** and **Blind SSRF with Shellshock exploitation** — both labs state outright that the lab's own network firewall blocks any callback to an external system *except* Burp Collaborator's default public server, specifically to prevent the Academy being used to attack third parties. That rules out any browser/curl-based workaround (e.g. webhook.site) — solving either lab genuinely requires the Collaborator client built into Burp Suite, which isn't part of this workflow. Same category of skip as the Collaborator-gated CSWSH lab noted on Day 6.

---

# Part 2: Path Traversal

## Lab 1: File path traversal, simple case
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/file-path-traversal/lab-simple

**Vulnerability:** The `/image?filename=` endpoint concatenates the `filename` parameter directly onto a base image directory with no sanitization at all.

**Steps:**
1. Found product images loaded via `/image?filename=14.jpg`.
2. Requested `/image?filename=../../../etc/passwd` — the server walked up out of the images directory and returned the contents of `/etc/passwd`, solving the lab immediately.

**Takeaway:** The baseline case for this whole topic: with zero sanitization, `../` sequences let you walk anywhere the web server process has filesystem read access to.

---

## Lab 2: File path traversal, traversal sequences blocked with absolute path bypass
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-path-traversal/lab-absolute-path-bypass

**Vulnerability:** The server strips `../` traversal sequences from the filename, but doesn't validate that the result is still a relative path underneath the intended directory.

**Steps:**
1. Requested `/image?filename=../../../etc/passwd` — blocked as expected (no traversal sequences survive).
2. Requested `/image?filename=/etc/passwd` (a bare absolute path, no `../` needed) — the server passed it straight to the filesystem API, which happily honors an absolute path regardless of the intended base directory, solving the lab.

**Takeaway:** Stripping traversal sequences doesn't help if the underlying file-read call also accepts absolute paths — the sanitization needs to enforce that the final resolved path stays inside the allowed directory, not just block one specific way of leaving it.

---

## Lab 3: File path traversal, traversal sequences stripped non-recursively
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-path-traversal/lab-sequences-stripped-non-recursively

**Vulnerability:** The server strips `../` from the filename, but only does a single pass — it doesn't re-check the result for new traversal sequences that stripping might have created.

**Steps:**
1. Requested `/image?filename=....//....//....//etc/passwd` — each `....//` has its inner `../` removed by a single non-recursive strip, leaving behind exactly `../` again, which was never re-scanned.
2. This resolved to `/etc/passwd`, solving the lab.

**Takeaway:** A sanitizer that removes a bad pattern in one pass can be defeated by nesting the pattern inside itself, so that removal *produces* a fresh instance of the very thing it was trying to block. Sanitization needs to loop until no more replacements occur, not run once.

---

## Lab 4: File path traversal, traversal sequences stripped with superfluous URL-decode
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-path-traversal/lab-superfluous-url-decode

**Vulnerability:** The server URL-decodes the filename parameter, strips `../` sequences, and then performs a *second*, superfluous URL-decode before using the value — creating a gap between what was sanitized and what actually gets used.

**Steps:**
1. Requested `/image?filename=..%2f..%2f..%2fetc/passwd` (single-encoded) — blocked, since the framework's normal decode already turns this into `../../../etc/passwd` before the traversal-sequence strip runs.
2. Requested `/image?filename=..%252f..%252f..%252fetc/passwd` (double-encoded — `%25` is an encoded `%`). The first, framework-level decode turns this into `..%2f..%2f..%2fetc/passwd`, which contains no literal `../` for the strip step to catch. The application's own *extra* decode step then turns the surviving `%2f` into `/`, reassembling `../../../etc/passwd` after the sanitizer has already run.
3. This resolved to `/etc/passwd`, solving the lab.

**Takeaway:** Decoding input more than once (or at a different layer than where sanitization happens) opens a gap where an encoded payload sails through the filter looking harmless, then gets "unwrapped" into something dangerous immediately afterward.

---

## Lab 5: File path traversal, validation of start of path
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-path-traversal/lab-validate-start-of-path

**Vulnerability:** The server checks that the filename *starts with* the expected base directory (e.g. `/var/www/images/`) before using it, but doesn't stop `../` sequences later in the same string from walking back out of that directory.

**Steps:**
1. Requested `/image?filename=/var/www/images/../../../etc/passwd` — the string starts with the required prefix (satisfying the validation check), but the trailing `../../../` still resolves the path back out to `/etc/passwd` once the filesystem processes it.
2. This solved the lab.

**Takeaway:** Validating a prefix says nothing about where the path ends up once traversal sequences later in the string are resolved — prefix checks and path-resolution checks are not the same thing.

---

## Lab 6: File path traversal, validation of file extension with null byte bypass
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-path-traversal/lab-validate-file-extension-null-byte-bypass

**Vulnerability:** The server requires the filename to end in `.png`, but the underlying (native/C-based) file-read API treats a null byte as a string terminator, while the higher-level validation logic doesn't.

**Steps:**
1. Requested `/image?filename=../../../etc/passwd%00.png` — the extension check sees a string that legitimately ends in `.png` and passes it, but the OS-level file API stops reading the filename at the `%00` (null byte), so it actually opens `/etc/passwd`, ignoring everything after the null byte.
2. This solved the lab.

**Takeaway:** A null byte creates a semantic mismatch between validation code that treats a filename as a normal string (so it sees the trailing `.png`) and lower-level file APIs that treat it as a null-terminated C string (so they stop early). This is an older/legacy bug class, but a good illustration of how a validation layer and an execution layer parsing the "same" string differently is a recurring root cause across many bypass techniques.

---

## A note on today's format

Today combines a partial SSRF run (4 of 7 labs — see "Labs not attempted" above for why) with a full Path Traversal run (6 of 6 labs) to reach the usual 10-lab total, rather than one topic alone. The two topics turned out to pair naturally: SSRF is fundamentally about a server following an attacker-controlled *location* (URL), while path traversal is about a server following an attacker-controlled *filesystem path* — the same underlying lesson (never trust a location string without validating where it actually resolves to) shows up in both.
