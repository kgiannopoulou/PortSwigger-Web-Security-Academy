# PortSwigger Web Security Academy — File Upload Vulnerabilities & Information Disclosure (Day 9)

My notes and write-ups from Day 9 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), **SSRF & Path Traversal** on [Day 7](day7-ssrf-and-path-traversal.md), and **XXE Injection & OS Command Injection** on [Day 8](day8-xxe-and-os-command-injection.md), today's run covers two topics: **File Upload Vulnerabilities** (all 7 labs) and **Information Disclosure** (3 labs), for 10 labs total.

## What are file upload vulnerabilities?

Almost every web application lets users upload something — an avatar, a document, an attachment — and every one of those upload functions is a potential vector for remote code execution if the server doesn't rigorously control what gets uploaded, where it's stored, and whether it can be executed afterward. The labs below all revolve around the same avatar-upload feature and repeatedly try to upload a PHP web shell (`<?php echo file_get_contents('/home/carlos/secret'); ?>`) to exfiltrate a secret file — each lab adds one more layer of validation (content-type checks, extension blacklists/whitelists, image-content validation, even an antivirus scan) that turns out to be bypassable in a different way.

## What is information disclosure?

Information disclosure happens when an application unintentionally reveals data about itself or its users that should have stayed private — stack traces with framework versions, debug endpoints, backup files containing source code, and similar leftovers. None of this is exploitation in the traditional sense; it's reconnaissance that hands an attacker exactly the details (a vulnerable dependency version, a hard-coded credential, an internal environment variable) needed to plan a real attack elsewhere.

---

# Part 1: File Upload Vulnerabilities

## Lab 1: Remote code execution via web shell upload
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload

**Vulnerability:** The avatar upload function performs no validation whatsoever on uploaded files — any file type, including executable server-side scripts, is accepted and stored directly under a web-accessible path.

**Steps:**
1. Logged in as `wiener:peter` and uploaded a file containing `<?php echo file_get_contents("/home/carlos/secret"); ?>` as the avatar.
2. The server stored it verbatim at `/files/avatars/<filename>.php`.
3. Requested that URL directly — the PHP executed server-side and returned the contents of `/home/carlos/secret`.
4. Submitted the secret to solve the lab.

**Takeaway:** The baseline case — zero validation on an upload endpoint is an instant path to remote code execution if the upload directory is ever reachable over HTTP and the server will execute scripts placed there.

---

## Lab 2: Web shell upload via Content-Type restriction bypass
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-content-type-restriction-bypass

**Vulnerability:** The server checks the client-supplied `Content-Type` header of the uploaded file part to decide whether to accept it — a purely client-controlled value that has nothing to do with the file's actual content.

**Steps:**
1. Uploaded the same PHP web shell, but set the multipart form part's `Content-Type` to `image/jpeg` instead of leaving it as the default.
2. The server trusted the header, accepted the file, and stored it as-is.
3. Requested the uploaded `.php` file directly and read the secret from the response.

**Takeaway:** `Content-Type` is just another attacker-controlled request header — validating file type based on it is equivalent to not validating at all.

---

## Lab 3: Web shell upload via path traversal
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-path-traversal

**Vulnerability:** PHP execution is disabled inside the `/files/avatars/` directory specifically, but the upload endpoint takes the client-supplied filename from the `Content-Disposition` header and uses it almost as-is to decide where on disk to save the file, only stripping literal `../` sequences.

**Steps:**
1. Confirmed that uploading `exploit.php` directly gets stored under `/files/avatars/`, but requesting it back returns the raw PHP source instead of executing it — execution is blocked in that directory.
2. Sent a raw multipart request with the file part's filename set to `../exploit.php`. The server's response ("The file avatars/exploit.php has been uploaded") showed the `../` had simply been stripped.
3. URL-encoded the slash instead — `filename="..%2fexploit.php"` — and re-sent the request. This time the response echoed back `avatars/../exploit.php`, proving the filename was being *URL-decoded* server-side, after the traversal check had already run.
4. Requested `/files/exploit.php` (one directory above `avatars/`, where PHP execution *is* allowed) and got the secret back.

**Takeaway:** Sanitizing traversal sequences before URL-decoding the input is a classic double-decode bypass — the same pattern seen with path traversal filters back on [Day 7](day7-ssrf-and-path-traversal.md#lab-4-file-path-traversal-traversal-sequences-stripped-with-superfluous-url-decode), just applied to an upload's filename instead of a `filename=` query parameter.

---

## Lab 4: Web shell upload via extension blacklist bypass
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass

**Vulnerability:** The server blacklists `.php` and similar known-dangerous extensions, but the underlying Apache server can be reconfigured per-directory via an uploaded `.htaccess` file — and `.htaccess` itself isn't on the blacklist.

**Steps:**
1. Confirmed a direct `.php` upload was rejected ("Sorry, only JPG & PNG files are allowed"-style message) but that the blacklist didn't cover `.htaccess`.
2. Uploaded a file named `.htaccess` (Content-Type `text/plain`) containing the Apache directive `AddType application/x-httpd-php .l33t`, which tells Apache to treat any file with the arbitrary `.l33t` extension as executable PHP.
3. Uploaded the web shell again, this time named `exploit.l33t`.
4. Requested `/files/avatars/exploit.l33t` — Apache applied the new handler mapping and executed it as PHP, returning the secret.

**Takeaway:** A file-extension blacklist can never be complete if the upload directory allows uploading server configuration files like `.htaccess` — that single file can retroactively make *any* other extension executable.

---

## Lab 5: Web shell upload via obfuscated file extension
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-obfuscated-file-extension

**Vulnerability:** The server only allows `.jpg`/`.png` extensions, checked against the end of the filename — but it also performs a legacy null-byte-unsafe string operation when actually saving the file to disk.

**Steps:**
1. Sent a raw multipart upload with the filename `exploit.php%00.jpg` (a literal, percent-encoded null byte between the dangerous and "safe" extensions).
2. The extension check saw a string ending in `.jpg` and allowed it through; the server's response then referred to the stored file as plain `exploit.php`, confirming the null byte and everything after it had been truncated when the file was actually written to disk.
3. Requested `/files/avatars/exploit.php` and got the secret back.

**Takeaway:** Extension validation and file-saving logic operating on the filename differently (one honoring the full string, the other truncating at a null byte) recreates the classic PHP null-byte injection bug even in a modern stack, as long as *any* code path along the way still treats the filename as a C-style string.

---

## Lab 6: Remote code execution via polyglot web shell upload
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-polyglot-web-shell-upload

**Vulnerability:** The server actually inspects the *contents* of the uploaded file to confirm it's a genuine image, defeating every filename-based trick used so far — but it still allows the accepted image to be requested with a `.php` extension and executed.

**Steps:**
1. Generated a minimal valid JPEG, then manually inserted a JPEG COM (comment) marker segment (`0xFFFE`) right after the file's `SOI` header, containing the payload `<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>`. This keeps the file a byte-for-byte valid, parseable JPEG — the PHP code just lives inside an ignored metadata field — equivalent to what the PortSwigger-suggested `exiftool -Comment=...` command produces.
2. Uploaded the file with a `.php` extension. Since it passed image-content validation (e.g. `getimagesize()`-style checks), the server accepted it.
3. Requested `/files/avatars/<file>.php` — the server executed it as PHP, ignoring the fact that most of the file is binary JPEG data, and the `START ... END` markers isolated the secret in the response body.

**Takeaway:** Content-based image validation only proves a file *contains* a valid image structure somewhere — it says nothing about whether the file *also* contains something else the interpreter downstream (PHP, here) will happily execute. A polyglot file can satisfy both parsers at once.

---

## Lab 7: Web shell upload via race condition
**Difficulty:** Expert
**Link:** https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-race-condition

**Vulnerability:** The server performs "robust" validation — but asynchronously: the uploaded file is written to a web-accessible directory *first*, then scanned for malicious content, and only deleted afterward if it fails the scan. That leaves a window where the file exists on disk and is servable before it's removed.

**Steps:**
1. Confirmed a direct PHP upload was accepted onto disk (200 response) but became unreachable moments later — the antivirus check deletes it shortly after upload.
2. Wrote a Python script using raw TLS sockets to replicate Burp Turbo Intruder's "last-byte synchronization" technique: opened one connection for the malicious `POST /my-account/avatar` upload and twenty connections for `GET /files/avatars/<shell>.php`, sent every byte of every request *except the final byte*, then released the final byte on all twenty-one sockets from parallel threads almost simultaneously, so all requests land on the server back-to-back.
3. Most of the GET requests landed in the brief window between the file being written and the antivirus scan deleting it, returning `200 OK` with Carlos's secret in the body.
4. Submitted the secret to solve the lab.

**Takeaway:** "Validate then delete if bad" is fundamentally different from "validate before making accessible" — any gap between a file becoming servable and a security check completing is a race condition, and with enough concurrent requests even a narrow window becomes reliably exploitable. The same last-byte-sync request-racing technique used for the [Day 5](day5-business-logic-vulnerabilities.md) gift-card redemption loop applies here too, just aimed at a validation window instead of a business-logic check.

---

# Part 2: Information Disclosure

## Lab 8: Information disclosure in error messages
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages

**Vulnerability:** The application returns full, unhandled stack traces to the client when it hits an unexpected input, and the stack trace footer reveals the exact framework and version in use.

**Steps:**
1. Requested `/product?productId=abc` — a non-numeric value where the app expects an integer.
2. The server returned an unhandled `NumberFormatException` with a full Java stack trace, ending with `Apache Struts 2 2.3.31`.
3. Submitted that version string to solve the lab.

**Takeaway:** Verbose error messages are reconnaissance gold — this one exact version string is enough to look up known CVEs (Struts 2.3.x has several serious ones) and skip straight to exploiting a documented vulnerability instead of hunting for one from scratch.

---

## Lab 9: Information disclosure on debug page
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-on-debug-page

**Vulnerability:** A leftover PHP debug endpoint (`phpinfo()`) is reachable in production and dumps the entire PHP environment, including server-side environment variables.

**Steps:**
1. Requested `/cgi-bin/phpinfo.php` directly and got a full `phpinfo()` output.
2. Searched the page for `SECRET_KEY` and found it listed under both the raw environment table and PHP's `$_SERVER` superglobal dump.
3. Submitted the value to solve the lab.

**Takeaway:** `phpinfo()` pages are a textbook example of a debug tool that's meant for local development but frequently gets shipped to production by accident — it leaks paths, environment variables, loaded modules and configuration that should never be attacker-visible.

---

## Lab 10: Source code disclosure via backup files
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-via-backup-files

**Vulnerability:** A `/backup` directory containing raw `.java` source files is deployed alongside the application, and its existence is even advertised in `robots.txt`.

**Steps:**
1. Requested `/robots.txt` and found `Disallow: /backup` — a hint at a directory the site owner didn't want crawled (and therefore didn't want found).
2. Requested `/backup/ProductTemplate.java.bak` and got the raw Java source for the class that builds the app's database connection.
3. Found a hard-coded Postgres password passed directly to the `JdbcConnectionBuilder` constructor in the source.
4. Submitted the password to solve the lab.

**Takeaway:** `robots.txt` is a list of paths the site owner doesn't want *search engines* indexing — it says nothing about access control, and to an attacker it often reads as a curated list of "interesting things to check first." Combined with editors/build tools that leave `.bak` files behind, it's a reliable way to stumble onto full source code, including hard-coded secrets.

---

## A note on tooling

All ten labs in this set were solved entirely with `curl`, Python (`http.client`/raw `ssl` sockets for the race condition, and Pillow for building the polyglot JPEG) — no browser interaction was needed beyond launching each lab instance and logging in once as `wiener`. The race-condition lab in particular reused the same "queue every request, release the final byte on all of them at once" trick that Burp's Turbo Intruder automates, just implemented directly against raw TLS sockets.
