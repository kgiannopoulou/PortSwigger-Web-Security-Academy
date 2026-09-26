# PortSwigger Web Security Academy — Server-Side Template Injection & NoSQL Injection (Day 13)

My notes and write-ups from Day 13 of learning web application security on [PortSwigger's Web Security Academy](https://portswigger.net/web-security). After **Access Control** on [Day 1](day1-access-control.md), **Authentication** on [Day 2](day2-authentication.md), **SQL Injection** on [Day 3](day3-sql-injection.md), **Cross-Site Scripting** on [Day 4](day4-cross-site-scripting.md), **Business Logic Vulnerabilities** on [Day 5](day5-business-logic-vulnerabilities.md), **Cross-Site Request Forgery** on [Day 6](day6-csrf.md), **SSRF & Path Traversal** on [Day 7](day7-ssrf-and-path-traversal.md), **XXE Injection & OS Command Injection** on [Day 8](day8-xxe-and-os-command-injection.md), **File Upload Vulnerabilities & Information Disclosure** on [Day 9](day9-file-upload-and-information-disclosure.md), **Prototype Pollution** on [Day 10](day10-prototype-pollution.md), **JWT Attacks & Clickjacking** on [Day 11](day11-jwt-and-clickjacking.md), and **API Testing & GraphQL API Vulnerabilities** on [Day 12](day12-api-testing-and-graphql.md), today's topics are two server-side injection classes: **Server-Side Template Injection** (5 labs) and **NoSQL Injection** (2 labs). The remaining labs in each topic — the Freemarker sandbox escape and the blind, character-by-character NoSQL data-extraction labs — are set aside for a future revisit.

## What is server-side template injection?

Template engines (ERB, Freemarker, Jinja, Handlebars, Tornado, the Django template language, …) build pages by merging a fixed template with runtime data. Server-side template injection (SSTI) happens when user input is concatenated **into the template string itself** rather than passed in as a data value — so `render("Hello " + name)` lets an attacker put template syntax in `name` and have the engine evaluate it server-side. The impact ranges from information disclosure (reading framework internals like a secret key) up to full remote code execution, depending on the engine and how locked-down it is. The methodology is always the same three steps: **detect** (fuzz with `${{<%[%'"}}%\` and probe with a math operation like `7*7`), **identify** the exact engine (each has a tell — a distinctive error message, or a payload like `{{7*'7'}}` that gives `49` in Twig but `7777777` in Jinja2), then **exploit** using that engine's specific syntax.

## What is NoSQL injection?

NoSQL databases like MongoDB don't use SQL, but they're still injectable when untrusted input reaches a query unsafely. There are two distinct flavours. **Syntax injection** breaks out of a query string much like classic SQLi — injecting quotes and operators to change how the query is parsed. **Operator injection** is unique to NoSQL: because these databases accept query *objects*, an app that lets user input become part of that object can be fed MongoDB query operators such as `$ne` (not equal), `$regex`, `$gt`, or `$where`. Slipping a `{"$ne":""}` where the app expected a plain string turns "password equals X" into "password is anything", which is enough to walk straight past an authentication check.

## Lab 1: Basic server-side template injection
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic

**Vulnerability:** An out-of-stock product renders a status message through an ERB (Ruby) template, with the message text concatenated directly into the template. The message is passed on the home page as the `message` GET parameter.

**Steps:**
1. Viewing any product redirects to `/?message=Unfortunately this product is out of stock`, showing the `message` parameter is reflected through the template.
2. Confirmed ERB evaluation by requesting `/?message=INJ<%= 7*7 %>END` — the response contained `INJ49END`, proving the math ran server-side.
3. Swapped in an ERB code-execution payload: `/?message=<%= system("rm /home/carlos/morale.txt") %>`. ERB's `<%= %>` evaluates the expression, `system()` shelled out to delete the file, and the lab was marked solved.

**Takeaway:** ERB exposes `system()` directly in the default rendering context, so the moment `7*7` evaluates you already have RCE — no sandbox to escape. The `7*7` probe is worth doing before assuming a reflected value is "just XSS".

---

## Lab 2: Basic server-side template injection (code context)
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-basic-code-context

**Vulnerability:** The "preferred name" account setting (`blog-post-author-display`) is inserted into a Tornado (Python) template in *code context* — the value is placed inside a `{{ ... }}` expression rather than as plain text, so a valid value is `user.name`. Breaking out of that expression allows arbitrary template code.

**Steps:**
1. Logged in as `wiener:peter`. The account page offers to display the author name as `user.name` or `user.first_name`, submitted via `/my-account/change-blog-post-author-display`.
2. Set the value to `user.name}}{% import os %}{{os.system("rm /home/carlos/morale.txt")` — the `}}` closes the original expression, `{% import os %}` imports the module in a statement block, and the final `{{os.system(...)}}` (closed by the template's own trailing `}}`) runs the command.
3. The payload only renders when the author name is displayed, so I posted a comment on a blog post and reloaded it. Rendering the comment's author name executed the code and solved the lab.

**Takeaway:** Code context is easy to miss because it produces no obvious XSS — it looks like a harmless hashmap lookup. The exploit isn't a reflected value but a *stored* one that only detonates when the object it belongs to is rendered somewhere.

---

## Lab 3: Server-side template injection using documentation
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-using-documentation

**Vulnerability:** Users with content-manager privileges can edit a product's description template directly. The engine is Apache Freemarker (Java), which — per its own documentation — ships a built-in utility class for executing OS commands.

**Steps:**
1. Logged in as `content-manager:C0nt3ntM4n4g3r` and opened the "Edit template" feature at `/product/template?productId=1`.
2. From the Freemarker docs, `freemarker.template.utility.Execute` runs shell commands when instantiated with `?new()`. Submitted the template `${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}` via the "preview" action.
3. The preview rendered the payload, executing the command and solving the lab.

**Takeaway:** When an app deliberately lets a privileged role write raw templates, "reviewing the documentation" *is* the exploit — the engine's own sanctioned features (here, the `Execute` utility) are the attack surface. Feature-by-design is still RCE if the role is ever compromised.

---

## Lab 4: Server-side template injection in an unknown language with a documented exploit
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-in-an-unknown-language-with-a-documented-exploit

**Vulnerability:** The out-of-stock `message` parameter is again rendered through a template, but this time the engine is unknown and must be fingerprinted first. It turned out to be Handlebars running on Node.js.

**Steps:**
1. Fuzzed the `message` parameter with `${{<%[%'"}}%\`; the resulting error message referenced `handlebars` and a `parseError`, identifying the engine.
2. Handlebars is logic-less and blocks direct code execution, so I used the well-known published RCE chain that abuses `#with`, `lookup`, and `constructor` to reach `require('child_process')`:
   ```handlebars
   {{#with "s" as |string|}}
     {{#with "e"}}
       {{#with split as |conslist|}}
         {{this.pop}}
         {{this.push (lookup string.sub "constructor")}}
         {{this.pop}}
         {{#with string.split as |codelist|}}
           {{this.pop}}
           {{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}}
           {{this.pop}}
           {{#each conslist}}
             {{#with (string.sub.apply 0 codelist)}}
               {{this}}
             {{/with}}
           {{/each}}
         {{/with}}
       {{/with}}
     {{/with}}
   {{/with}}
   ```
3. URL-encoded and delivered it via `message`; the chain built and invoked a function that ran the command, solving the lab.

**Takeaway:** A "logic-less" template engine isn't automatically safe — Handlebars still exposes enough primitives (`constructor`, `lookup`, `apply`) to reconstruct a `Function` and reach Node's `child_process`. Fingerprinting the engine from its error output is the whole game; the exploit itself is a copy-paste once you know it's Handlebars.

---

## Lab 5: Server-side template injection with information disclosure via user-supplied objects
**Difficulty:** Practitioner
**Link:** https://portswigger.net/web-security/server-side-template-injection/exploiting/lab-server-side-template-injection-with-information-disclosure-via-user-supplied-objects

**Vulnerability:** The content-manager template editor uses the Django template language. Django's template sandbox blocks calling functions and accessing dunder attributes, so RCE isn't straightforward — but the template context still exposes the framework's `settings` object, which leaks the secret key.

**Steps:**
1. Logged in as `content-manager:C0nt3ntM4n4g3r` and opened the template editor.
2. Submitted `{{settings.SECRET_KEY}}` as the template and previewed it. Django resolved the attribute lookup and rendered the framework's `SECRET_KEY` straight into the page.
3. Submitted the recovered key as the lab answer, which returned `{"correct":true}` and solved the lab.

**Takeaway:** A sandboxed engine that blocks RCE can still be a serious information-disclosure hole. Django forbids callables and `__dunder__` traversal, but a plain attribute chain like `settings.SECRET_KEY` is perfectly legal — and a leaked secret key undermines every signed cookie and token the app issues.

---

## Lab 6: Detecting NoSQL injection
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-detection

**Vulnerability:** The product category filter passes the `category` value into a MongoDB query unsafely, allowing syntax injection that rewrites the query's boolean logic.

**Steps:**
1. The `Gifts` category returned 3 products as a baseline.
2. Injected a query that is always true: `/filter?category=Gifts'||1||'`. The `'` breaks out of the original string and `||1||` forces the whole condition to evaluate truthy.
3. The response jumped from 3 to all 20 products — including unreleased ones that shouldn't be visible — which solved the lab.

**Takeaway:** NoSQL is just as injectable as SQL when input is concatenated into a query. A simple always-true boolean (`'||1||'`) is the NoSQL analogue of `' OR 1=1 --`, and here it exposed hidden records by defeating a category filter.

---

## Lab 7: Exploiting NoSQL operator injection to bypass authentication
**Difficulty:** Apprentice
**Link:** https://portswigger.net/web-security/nosql-injection/lab-nosql-injection-bypass-authentication

**Vulnerability:** The login endpoint accepts a JSON body and builds its MongoDB query from those fields without validating their types, so an attacker can supply MongoDB query *operators* in place of the expected string values.

**Steps:**
1. Sent the login as JSON and replaced the plain string values with operators: `{"username":{"$regex":"admin.*"},"password":{"$ne":"x"}}`.
2. `$regex":"admin.*"` matches any username starting with `admin` (the real admin account wasn't literally `administrator` — it was `admin04d8k8ir`), and `$ne":"x"` matches any password that isn't `x`.
3. The server matched the admin record and issued a redirect to `/my-account?id=admin04d8k8ir`, logging me in as the administrator and solving the lab.

**Takeaway:** Operator injection is the NoSQL-specific trap: the danger isn't a quote character but the fact that a JSON value can be an *object* (`{"$ne":""}`) instead of a string. The `$regex` operator doubles as a discovery tool here — it revealed that the admin username wasn't the obvious guess, something an exact-match payload would have missed.

---

## Closing note

Both topics share the same root cause seen all week: **untrusted input crossing from "data" into "code."** In SSTI it crosses into the template that the engine executes; in NoSQL injection it crosses into the query object the database evaluates. The defence is identical in spirit too — keep user input strictly as a passed-in *value* (template variables, typed/validated query parameters), never let it become part of the executed template string or query structure, and, where a privileged template-editing feature is genuinely required, run the engine in the most locked-down sandbox available.

A neat cross-topic detail: the same `7*7` idea powers both detection routines. In SSTI you inject `7*7` and look for `49` in the output; in NoSQL you inject an always-true (`'||1||'`) or an operator (`$ne`) and look for the result set or the auth check to flip. In every case you're probing whether the server *evaluates* your input rather than merely storing it.
