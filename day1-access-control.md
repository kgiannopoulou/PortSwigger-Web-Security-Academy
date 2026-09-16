# PortSwigger Web Security Academy — Access Control (Day 1)

I started with the **Access Control** topic and worked through 10 labs (9 Apprentice-level, 1 Practitioner-level).

This is my first day doing hands-on security labs, so these write-ups are intentionally detailed — they're as much for my own reference later as for anyone else starting out.

## What is "Access Control"?

Access control vulnerabilities happen when an application fails to properly verify that a user is allowed to do something (authorization), even if it correctly verifies who they are (authentication). The core lesson across every lab below: **never trust the client**. Whether it's a URL, a cookie, a request parameter, or a hidden form field, if a security decision depends on data the user controls, it can be tampered with.

---

## Lab 1: Unprotected admin functionality
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

**Vulnerability:** The admin panel has no authentication or authorization check at all — anyone who finds the URL can use it.

**Steps:**
1. Tried the obvious path `/admin` → "Not Found".
2. Checked `/robots.txt` → it disclosed `Disallow: /administrator-panel`. (`robots.txt` only asks search engines not to *index* a path — it doesn't block access to it, so this file actually leaked the hidden panel's location.)
3. Navigated to `/administrator-panel` → the admin panel loaded with no login required.
4. Clicked **Delete** next to `carlos` → lab solved.

**Takeaway:** Security through obscurity (hiding a URL) is not real access control, and using `robots.txt` to "hide" something is actively counterproductive.

---

## Lab 2: Unprotected admin functionality with unpredictable URL
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url

**Vulnerability:** Same as Lab 1 — no authentication on the admin panel — but this time the URL is a random string instead of a guessable path. The location is leaked elsewhere in the app instead of `robots.txt`.

**Steps:**
1. Viewed the home page source (`Ctrl+U`) and searched (`Ctrl+F`) for the word `admin`.
2. Found a hidden reference to the admin path in the page source: a random suffix like `admin-o9m993`.
3. Navigated to `https://<lab-id>.web-security-academy.net/admin-<random>`.
4. Clicked **Delete** next to `carlos` → lab solved.

**Takeaway:** A random/unguessable URL is still just obscurity, not access control — if it's referenced anywhere in the client-side code, it will leak.

---

## Lab 3: User role controlled by request parameter
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter

**Vulnerability:** The application decides whether a user is an admin based on a client-side cookie (`Admin=false`), which the server trusts without verifying — meaning it can simply be forged by the client.

**Steps:**
1. Logged in as `wiener` / `peter`.
2. Opened DevTools (`F12`) → **Application** tab → **Cookies** → found a cookie: `Admin = false`.
3. Edited the value to `true` and saved it.
4. Navigated to `/admin` → recognized as admin.
5. Deleted `carlos` → lab solved.

**Takeaway:** Cookies (and any client-side state) are fully controlled by the user. Authorization decisions must be verified server-side, never trusted from a client-supplied value.

---

## Lab 4: User role can be modified in user profile
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile

**Vulnerability:** Mass assignment / excessive data binding. The admin panel checks a server-side `roleid` field. The visible "change email" feature never exposes a way to edit that field, but the underlying endpoint blindly applies *any* field present in the request body — including one the UI never sends.

**Steps:**
1. Logged in as `wiener` / `peter`, opened DevTools → **Network** tab, enabled **Preserve log**, filtered to **Fetch/XHR**.
2. Submitted an email change and inspected the resulting `change-email` POST request — its JSON body was just `{"email":"..."}`, with no role field.
3. Right-clicked the request → **Copy** → **Copy as fetch**, pasted it into the Console.
4. Edited the `body` to add a role parameter: `{"email":"...","roleid":2}`, then ran it.
5. Navigated to `/admin` → recognized as admin.
6. Deleted `carlos` → lab solved.

**Takeaway:** Never assume the server only accepts the fields your UI sends. Backend code that does something like "apply all fields from this object to the user record" is a mass assignment vulnerability waiting to happen.

---

## Lab 5: User ID controlled by request parameter
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter

**Vulnerability:** Horizontal privilege escalation — the account page URL includes `?id=<username>`, and the server doesn't check that the logged-in user actually owns that ID.

**Steps:**
1. Logged in as `wiener` / `peter`. My own account URL was `/my-account?id=wiener`.
2. Changed the URL to `/my-account?id=carlos`.
3. The page loaded carlos's account, including his API key.
4. Submitted his API key as the lab solution.

**Takeaway:** "Horizontal" privilege escalation means accessing another regular user's data (not admin data) just by changing an identifier the client controls.

---

## Lab 6: User ID controlled by request parameter, with unpredictable user IDs
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids

**Vulnerability:** Same horizontal privilege escalation as Lab 5, but users are identified by GUIDs instead of usernames, so the ID can't just be guessed — it has to be found somewhere in the app.

**Steps:**
1. Noticed the home page is actually a blog (list of posts), even though there's no nav link labeled "Blog".
2. Opened a blog post and scrolled to its comments.
3. Found a comment from `carlos`, whose name linked to `/blogs?userId=<GUID>` — that GUID is his real account ID.
4. Went to `/my-account?id=<carlos's GUID>` and retrieved his API key.
5. Submitted it as the lab solution.

**Takeaway:** Switching from sequential/guessable IDs to random GUIDs doesn't fix a broken access control check — it only removes the ability to *guess* IDs. If the ID leaks anywhere else in the app (comments, profile links, etc.), the vulnerability is exactly as exploitable.

---

## Lab 7: User ID controlled by request parameter with data leakage in redirect
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect

**Vulnerability:** The server *does* correctly detect the unauthorized access and issues an HTTP redirect (3xx) away from carlos's account page — but the actual body of that redirect response was already rendered with carlos's data before the redirect was added, and the body is sent anyway.

**Steps:**
1. Requesting `/my-account?id=carlos` in a normal browser just shows your own account, because the browser silently follows the redirect and Chrome's DevTools doesn't reliably expose the body of a redirected top-level navigation.
2. Retrieved the session cookie value from DevTools → Application → Cookies.
3. Used `curl` directly against the endpoint with `--max-redirs 0` (so it does not follow the redirect) and the session cookie in the request header, to see the raw response body.
4. The 302 response body contained carlos's fully rendered account page, including his API key.
5. Submitted it as the lab solution.

**Takeaway:** A redirect doesn't erase a response body that was already generated. Access control checks need to happen *before* any sensitive data is rendered into a response, not just before deciding where to send the browser next. Tools like Burp Suite (or plain `curl`) are useful here because they show you the raw HTTP traffic that the browser normally hides.

---

## Lab 8: User ID controlled by request parameter with password disclosure
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure

**Vulnerability:** The account page pre-fills the current password into a masked (`type="password"`) input. Visually it just shows dots, but the actual plaintext value is present in the page's raw HTML `value` attribute.

**Steps:**
1. Logged in as `wiener` / `peter`.
2. Requested `/my-account?id=administrator`.
3. Viewed the raw HTML response and found `<input type="password" name="password" value="..."/>` containing the administrator's real password in plaintext.
4. Logged out, logged back in as `administrator` with that password.
5. Went to `/admin` and deleted `carlos` → lab solved.

**Takeaway:** Masking an input visually (dots on screen) is a UI convenience, not a security control — the actual value is still transmitted and present in the HTML/DOM unless it's genuinely omitted from the response.

---

## Lab 9: Insecure direct object references
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references

**Vulnerability:** The site's live chat feature saves each chat transcript as a sequentially numbered static file (`/download-transcript/1.txt`, `2.txt`, ...) with no check on who is allowed to read which file number.

**Steps:**
1. Opened the "Live chat" feature and used "View transcript" to see how it worked — it triggers a request to `/download-transcript`, which responds with a redirect to a numbered file like `/download-transcript/2.txt`.
2. Requested a lower-numbered file directly, `/download-transcript/1.txt`, without ever having created it myself.
3. It contained a pre-existing transcript where a user (carlos) was socially engineered by a fake "support agent" into typing out his own password to "confirm" it.
4. Logged in as `carlos` using the password found in that transcript → lab solved.

**Takeaway:** "Insecure Direct Object Reference" (IDOR) means an internal object (a file, a database row, a resource ID) is exposed directly via a client-controllable reference (like a filename or numeric ID) without checking that the requester actually owns that object.

---

## Lab 10: URL-based access control can be circumvented
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/access-control/lab-url-based-access-control-can-be-circumvented

**Vulnerability:** A front-end reverse proxy blocks direct requests to `/admin` based on the request path. However, the back-end application (built on a framework that honors the `X-Original-URL` header) uses that header's value to determine the *actual* route to serve, instead of the real request path.

**Steps:**
1. Sent a request to the site's root `/` (which the front-end proxy allows) with an added header: `X-Original-URL: /admin`.
2. The front-end only checked the real path (`/`) and let it through; the back-end read `X-Original-URL` and served the admin panel content anyway.
3. To delete carlos, the query string (`?username=carlos`) had to be sent on the *actual* request URL (the header only carries the path, not query parameters), while `X-Original-URL: /admin/delete` redirected the routing:
   ```
   curl "https://<lab-id>.web-security-academy.net/?username=carlos" -H "X-Original-URL: /admin/delete"
   ```
4. Verified carlos was deleted by re-checking the admin panel via the same header trick.

**Takeaway:** Access control enforced only at the network/proxy layer (based on the visible URL path) can be bypassed if the back-end application trusts a different, attacker-controllable signal (like a custom header) to make its own routing decisions. Front-end and back-end must agree on what "the request" actually is.

---

## Overall takeaways from Day 1

- **Never trust client-side data** for authorization decisions — not cookies, not hidden form fields, not "hidden" or randomized URLs.
- **Verify authorization server-side, on every request**, not just at login or on the first page load.
- **A visible UI restriction is not a security control.** If the browser hides something (a masked password field, a grayed-out button, a missing link), that doesn't mean the underlying request is actually blocked.
- **Access control checks must happen before data is rendered**, not just before deciding where to redirect the user.
- Tools like the browser's DevTools (Network/Application tabs) and `curl` are enough to find and exploit most of these issues — Burp Suite makes it faster and easier for more advanced cases, but isn't strictly required for the basics.
