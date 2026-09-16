# PortSwigger Web Security Academy — Cross-Site Scripting (Day 4)

My notes and write-ups from Day 4 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), and **SQL Injection** on [Day 3](day3-sql-injection.md), I moved on to the **Cross-Site Scripting (XSS)** topic and worked through 10 labs (9 Apprentice-level, 1 Practitioner-level).

## What is "cross-site scripting"?

XSS happens when an application takes attacker-controlled input and places it somewhere a browser will interpret it as code rather than as data — inside raw HTML, inside an HTML attribute, inside a JavaScript string, or as an argument to a DOM sink like `document.write()` or `innerHTML`. Every lab below abuses that same root cause from a different angle: no encoding at all, angle brackets encoded but quotes left alone, a JavaScript-string context reachable only by breaking out of the quotes, and DOM-based sinks fed directly from the URL rather than server templating. The recurring lesson: **the correct defense depends entirely on *where* the input ends up** — the encoding that protects an HTML text node does nothing to protect an attribute value or a JavaScript string, and injected markup that a normal element would render can be completely inert if it lands inside something like a `<select>`.

---

## Lab 1: Reflected XSS into HTML context with nothing encoded
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded

**Vulnerability:** The search results page reflects the `search` query parameter directly into the page body with no encoding at all, so any HTML submitted in the query string is rendered as real markup.

**Steps:**
1. Submitted `?search=<script>alert(1)</script>` as the search term.
2. The server reflected the payload verbatim into the HTML response, so the browser parsed and executed the injected `<script>` tag on page load.
3. The `alert(1)` call fired → lab solved.

**Takeaway:** This is the baseline case with zero output encoding — the simplest possible XSS, and a good reminder of why *every* point where user input reaches HTML output needs context-aware encoding, not just the "obvious" ones.

---

## Lab 2: Stored XSS into HTML context with nothing encoded
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded

**Vulnerability:** The blog comment functionality stores the submitted comment text and renders it unescaped whenever the post is viewed, so a malicious comment executes for every visitor, not just the one who posted it.

**Steps:**
1. Opened a blog post and submitted a comment containing `<script>alert(1)</script>` as the comment body, with a name, email and website filled in.
2. Submitted the form. The lab flagged as solved immediately on submission — the comment content itself was enough to be recognized as a valid stored-XSS payload, without needing to revisit the post and watch it render.

**Takeaway:** Stored XSS is more dangerous than reflected because the payload persists and fires for *every* subsequent visitor, with no need to trick a specific user into clicking a crafted link — the attacker only has to get the payload accepted once.

---

## Lab 3: DOM XSS in document.write sink using source location.search
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink

**Vulnerability:** A client-side script reads the `search` term straight out of `location.search` and passes it to `document.write()` to echo it back into the page — entirely in the browser, with no server templating involved at all. The value is written inside an HTML attribute (an input's `value`), so the exploit has to break out of that attribute first.

**Steps:**
1. Submitted `?search="><img src=1 onerror=alert(1)>` — the `">` closes the existing attribute and tag, and the `<img>` with a deliberately broken `src` fires `onerror` immediately.
2. `document.write()` inserted this markup directly into the page, the image failed to load, and `onerror` called `alert(1)` → lab solved.

**Takeaway:** DOM-based XSS doesn't require the server to reflect anything — the vulnerable data flow (`location.search` → `document.write()`) exists entirely client-side. It's also the first of several labs in this set where the payload has to fire via an event handler (`onerror`) rather than a plain `<script>` tag, since the injection point is inside an existing attribute rather than free HTML.

---

## Lab 4: DOM XSS in innerHTML sink using source location.search
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-innerhtml-sink

**Vulnerability:** Same `location.search`-driven search-tracking pattern as Lab 3, but the value is assigned to an element's `innerHTML` instead of passed to `document.write()`.

**Steps:**
1. Submitted `?search=<img src=x onerror=alert(1)>`.
2. Because the sink is `innerHTML`, this couldn't use a plain `<script>` tag — browsers deliberately do not execute `<script>` elements inserted via `innerHTML`. An event-handler-based payload like `<img onerror>` sidesteps that restriction entirely, since `onerror` still fires normally on an image inserted this way.
3. The broken image's `onerror` handler called `alert(1)` → lab solved.

**Takeaway:** `innerHTML` is unsafe for untrusted data, but *not* in the same way `document.write()` or raw HTML output is — script tags are inert through `innerHTML`, so real-world filters that only worry about `<script>` miss this class of DOM XSS entirely. Event-handler attributes on ordinary tags are the standard bypass.

---

## Lab 5: DOM XSS in jQuery anchor href attribute sink using location.search source
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-href-attribute-sink

**Vulnerability:** The "submit feedback" page uses jQuery's `$()` selector to find a "Back" link and sets its `href` attribute from the `returnPath` URL parameter, with no validation on what kind of URL is allowed.

**Steps:**
1. Navigated to `/feedback?returnPath=javascript:alert(document.cookie)`.
2. jQuery wrote that value straight into the `href` attribute, producing `<a href="javascript:alert(document.cookie)">Back</a>`.
3. Clicked the "Back" link — clicking a `javascript:` URI executes it as code in the page's context.
4. `alert(document.cookie)` fired → lab solved.

**Takeaway:** A `javascript:` URI in an `href` is a full XSS sink, not just a bad practice — the exploit fires on user interaction (a click) rather than automatically on page load, which is worth remembering when reasoning about how "clickable" an otherwise-passive DOM sink actually is.

---

## Lab 6: DOM XSS in jQuery selector sink using a hashchange event
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-jquery-selector-hash-change-event

**Vulnerability:** The home page uses jQuery's `$()` selector function to auto-scroll to a blog post whose title is taken from `location.hash`, and re-runs this lookup every time a `hashchange` event fires. Passing arbitrary HTML as the selector string causes jQuery to parse and inject it into the DOM. Because the vulnerable code only re-triggers on `hashchange` — not on the page's *initial* hash — the exploit has to be delivered to a victim via the built-in exploit server rather than solved by simply visiting a crafted URL directly.

**Steps:**
1. On the exploit server, crafted a response body containing:
   ```html
   <iframe src="https://<lab-id>.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
   ```
   The iframe first loads the lab with an empty hash, then its `onload` handler appends the payload to the hash — which changes the hash *after* the initial load and therefore fires `hashchange` in the framed page.
2. Clicked **Store**, then **Deliver exploit to victim**.
3. The lab's simulated victim browser loaded the exploit page, triggered the crafted `hashchange`, and the injected `<img onerror>` called `print()` → lab solved.

**Takeaway:** Some DOM sinks only respond to events that don't fire on ordinary page load, so exploiting them for real (as opposed to just proving the concept against your own browser) means engineering a page that changes the hash *after* load to trigger the listener — this is also the first lab in the set solved by delivering an exploit to a separate victim rather than triggering it in my own session.

---

## Lab 7: Reflected XSS into attribute with angle brackets HTML-encoded
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-attribute-angle-brackets-html-encoded

**Vulnerability:** The search term is reflected inside an HTML attribute (the search box's `value`), and the application HTML-encodes `<` and `>` — but not double quotes — so a new tag can't be injected, but the existing tag's attribute list can still be extended.

**Steps:**
1. Submitted `?search=" onfocus="alert(1)" autofocus="`.
2. Since angle brackets are encoded but quotes aren't, this closed the `value` attribute, added a new `onfocus` handler and an `autofocus` attribute, then re-opened a quote to keep the rest of the tag's markup valid.
3. `autofocus` made the browser focus the input automatically on page load, immediately firing `onfocus` → `alert(1)` → lab solved.

**Takeaway:** Encoding only `<` and `>` stops new-tag injection but does nothing to stop *attribute* injection — `autofocus` + `onfocus` is the standard way to get an event handler to fire without needing a click or a broken resource, whenever quotes are left unescaped.

---

## Lab 8: Stored XSS into anchor href attribute with double quotes HTML-encoded
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-href-attribute-double-quotes-html-encoded

**Vulnerability:** The comment form's "website" field is rendered as the `href` of a link built around the commenter's name, and double quotes *are* HTML-encoded this time — which rules out breaking out of the attribute, but the value inside the attribute is otherwise used as-is.

**Steps:**
1. Posted a comment with the Website field set to `javascript:alert(document.cookie)` — no quote-breakout needed, since the entire attribute value becomes the `href` itself.
2. Submitted the form; the lab was marked solved immediately, purely from the stored comment content matching the expected payload — the same pattern seen in Lab 2, where PortSwigger's grading appears to validate the stored data server-side rather than requiring the payload to actually render and execute in a browser afterward.

**Takeaway:** When quotes are encoded but the field's value is otherwise trusted, injecting a `javascript:` URI as the *entire* attribute value sidesteps the encoding completely — there's no need to escape anything if the whole value you control is the dangerous part.

---

## Lab 9: Reflected XSS into a JavaScript string with angle brackets HTML encoded
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/cross-site-scripting/contexts/lab-javascript-string-angle-brackets-html-encoded

**Vulnerability:** The search term is reflected inside an inline `<script>` block, assigned to a JavaScript string variable (e.g. `var searchTerm = 'INJECTION';`). Angle brackets are HTML-encoded, which would stop a new `<script>` tag from being injected — but since the reflection point is already inside an existing script, that encoding is irrelevant; the real boundary to break is the quoted string.

**Steps:**
1. Submitted `?search='-alert(1)-'`.
2. The single quote closed the JavaScript string literal, `-alert(1)-` became a (nonsensical but syntactically valid) subtraction expression that still calls `alert(1)` as a side effect, and the trailing `'` re-opened a string to keep the rest of the original line syntactically valid.
3. The script executed inline with the rest of the page's script block → lab solved.

**Takeaway:** HTML-encoding `<` and `>` is meaningless once the injection point is already *inside* a `<script>` block — the relevant characters to escape there are the ones that terminate the current JavaScript string (quotes) or statement (semicolons), not HTML metacharacters.

---

## Lab 10: DOM XSS in document.write sink using source location.search inside a select element
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink-inside-select-element

**Vulnerability:** A product page's stock-checker widget reads a `storeId` parameter from `location.search` and writes it into the page via `document.write()`, inside a `<select>` element listing store locations. Browsers only allow `<option>`/`<optgroup>` as meaningful children of `<select>` — any other markup injected there (like a `<script>` or `<img>` tag) is either ignored or stripped of its usual behavior, so the injection has to escape the `<select>` context entirely before it can do anything.

**Steps:**
1. Requested `/product?productId=1&storeId=1</select><img src=1 onerror=alert(1)>`.
2. The injected `</select>` closed the select element early, so everything after it — the `<img>` tag — was parsed as ordinary page content outside any special content-model restrictions.
3. The broken image's `onerror` handler fired `alert(1)` → lab solved.

**Takeaway:** Where a payload lands structurally matters as much as what characters are or aren't encoded — some HTML elements (`<select>`, `<table>`, `<template>`, etc.) have their own parsing rules that neutralize otherwise-valid injected markup, and the fix is the same principle as breaking out of an attribute or a string: close the restrictive context first, *then* inject.

---

## A note on `alert()` and real browser dialogs

Several of these labs (3, 4, 7, 9, 10) require firing `alert()` (or `print()`, in Lab 6) via an event handler like `onerror`, `onload`, or `autofocus`/`onfocus` rather than a plain `<script>` tag — because the injection point sits inside an attribute, inside `innerHTML`, or inside a `<select>`, where `<script>` either can't be used or won't execute. Unlike a `<script>alert(1)</script>` payload parsed early during page load, these event-driven calls to `alert()` genuinely popped a native, blocking browser dialog box during testing, which had to be manually dismissed before automation could continue and confirm each "solved" state. It's a good reminder that `alert()`/`print()` are used in these labs purely as a harmless, unmistakable proof that arbitrary JavaScript executed — in a real attack, that same execution context would run entirely invisible code (cookie theft, session hijacking, keylogging) with no visible dialog at all.
