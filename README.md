# DVWA Security Walkthrough

> A practical, screenshot-supported study of common web application vulnerabilities using Damn Vulnerable Web Application (DVWA).

## Overview

This repository documents a local DVWA lab across all four DVWA security levels:

- **Low**: intentionally vulnerable behavior with little or no defensive code.
- **Medium**: partial defenses that can often be bypassed because they rely on incomplete filtering, browser controls, or context-specific escaping.
- **High**: stronger-looking defenses that still expose weaknesses when validation is too broad or another vulnerability can be chained with them.
- **Impossible**: the hardened reference implementation supplied by DVWA, demonstrating safer validation and coding patterns.

The walkthroughs focus on understanding *why* each vulnerability works, how the implementation changes between levels, what the observable result looks like, and which defensive design decisions close the issue.

The documented lab target is:

```text
http://127.0.0.1:42001
```

This is an educational repository for a deliberately vulnerable application. It is not a production penetration-testing guide and should only be used against a DVWA instance that you own or are explicitly authorized to test.

## Safety and Authorization

The payloads in these walkthroughs execute commands, read files, alter credentials, and extract database values. Use them only inside an isolated lab.

- Run DVWA locally or inside a disposable, isolated virtual machine.
- Keep the service bound to localhost where possible; do not expose this DVWA instance to the internet or an untrusted network.
- Test only the target and account you configured for this exercise.
- Never reuse these payloads against a third-party website, work system, public IP, or application without written authorization.
- Treat session cookies, password values, database output, and captured traffic as sensitive even in a lab.
- Reset the DVWA database and restore the intended security level between stateful exercises.

## What You Need

### Required

- A working DVWA installation.
- A browser with access to the DVWA web interface.
- An authenticated DVWA account, normally the default `admin` account in the local lab.
- Access to the **DVWA Security** page so the security level can be changed.
- A local Linux environment such as Kali Linux, or an equivalent environment capable of running DVWA.

### Used by Specific Walkthroughs

- **Burp Suite or browser developer tools** for inspecting requests, cookies, form fields, and source code. Burp is useful but not required for every chapter.
- **Python 3 and the `requests` package** for the automated blind SQL injection examples.
- **A local HTTP server** for the CSRF and reflected-XSS demonstrations. The CSRF walkthrough uses local Python servers on port `8888`.
- **A shell with common utilities** such as `base64` for decoding the PHP filter output in the file-inclusion chapter.

The repository contains walkthrough documentation and screenshots. Python, HTML, and server snippets shown in the chapters are instructional examples embedded in Markdown; they are not maintained as standalone scripts in this repository.

## Lab Assumptions

The walkthroughs were written against a local DVWA instance running on port `42001`, with exercises performed while logged in as `admin`. Individual environments may differ in their port, installation path, PHP configuration, browser behavior, or default database state. When your environment differs, substitute your own local values consistently.

The file-inclusion walkthrough assumes that `allow_url_include` is disabled, which is common on modern PHP installations. As a result, it concentrates on local file inclusion and PHP stream-wrapper behavior rather than remote PHP execution.

## Recommended Workflow

1. Start DVWA and confirm that the application loads at the expected local URL.
2. Log in and confirm that the account has access to the vulnerable modules.
3. Open **DVWA Security** and select the security level required by the chapter.
4. Read the normal behavior section before trying a payload. Establishing the expected response makes the later difference easier to identify.
5. Inspect the request, form, source, or response described by the walkthrough.
6. Reproduce the exercise against the local target only.
7. Verify the result using the method documented in that chapter. For state-changing exercises, do not infer success from a single page response when a login or database check is available.
8. Reset the database from **Setup / Reset DB** when the exercise changes credentials or database state.
9. Compare the vulnerable implementation with **Impossible** and identify the control that changes the input from executable syntax into validated data.

Keep the browser session and the selected DVWA security cookie aligned with the exercise. A request sent with the wrong `security` value, an expired `PHPSESSID`, or a stale password can look like a failed payload when the actual problem is lab state.

## Repository Map

| Path | Contents |
| --- | --- |
| [01-command-injection/](01-command-injection/) | Shell command injection at `/vulnerabilities/exec/`. |
| [02-csrf/](02-csrf/) | Cross-Site Request Forgery at `/vulnerabilities/csrf/`. |
| [03-file-inclusion/](03-file-inclusion/) | Local and remote file inclusion concepts at `/vulnerabilities/fi/`. |
| [04-sql-injection/](04-sql-injection/) | Visible SQL injection at `/vulnerabilities/sqli/`. |
| [05-sqli-blind/](05-sqli-blind/) | Boolean-based blind SQL injection at `/vulnerabilities/sqli_blind/`. |

Each numbered directory contains a chapter README and a `screenshots/` directory. The screenshots provide visual evidence for forms, source code, payload results, and verification steps.

## Learning Path

The chapters are numbered in a useful progression. Follow them in order if this is your first pass, or jump directly to a topic using the table below.

| Chapter | Vulnerability | Main idea | Defensive lesson |
| --- | --- | --- | --- |
| [01](01-command-injection/README.md) | Command Injection | User input becomes part of a shell command. | Validate the expected structure and avoid shell interpretation; do not rely on a blacklist. |
| [02](02-csrf/README.md) | CSRF | A browser sends its authenticated cookie with an attacker-triggered request. | Use anti-CSRF tokens, safe request semantics, origin protections, and re-authentication for sensitive actions. |
| [03](03-file-inclusion/README.md) | LFI/RFI | User input controls a path passed to PHP `include()`. | Map user choices to exact server-side filenames; never include arbitrary user-controlled paths. |
| [04](04-sql-injection/README.md) | SQL Injection | User input is concatenated into SQL syntax. | Use prepared statements and bind typed parameters; do not treat escaping as a universal fix. |
| [05](05-sqli-blind/README.md) | Blind SQL Injection | A yes/no response leaks database values one question at a time. | Fix the underlying injection and add appropriate authorization, rate limits, monitoring, and data protection. |

### 01 - Command Injection

[01-command-injection/README.md](01-command-injection/README.md) begins with a ping form and follows shell metacharacter bypasses through the four security levels. Low accepts an appended command, Medium misses alternate separators, and High contains a narrowly written pattern that can be bypassed with a pipe without a space. Impossible validates the structure of an IPv4 address, rebuilds it from numeric components, and only then invokes the command.

This chapter establishes a recurring theme: checking for known-bad characters is weaker than accepting only the exact shape of the expected value.

### 02 - Cross-Site Request Forgery

[02-csrf/README.md](02-csrf/README.md) uses the password-change form to show how a state-changing GET request can be triggered with the administrator's session cookie. It then examines a weak Referer check, a real token defense, and a token-stealing chain through reflected XSS. The Impossible level adds current-password verification while retaining the token and prepared SQL statements.

This chapter demonstrates that defenses interact. An anti-CSRF token is valuable, but same-origin XSS can read it and act inside the victim's session.

### 03 - File Inclusion

[03-file-inclusion/README.md](03-file-inclusion/README.md) explores the `page` parameter and PHP's `include()` behavior. It covers `/etc/passwd` reads, `php://filter` source disclosure, traversal bypasses, and the `file://` stream wrapper. Impossible maps input to four exact filenames instead of trying to strip dangerous patterns.

This chapter is also a reminder that a file-inclusion bug is not merely a path traversal issue. PHP wrappers and the execution behavior of `include()` can turn it into source disclosure or code execution depending on configuration.

### 04 - SQL Injection

[04-sql-injection/README.md](04-sql-injection/README.md) shows visible SQL injection against the user lookup form. Low demonstrates tautologies and `UNION SELECT`; Medium shows why a browser dropdown and quote escaping do not secure a numeric SQL context; High moves the value into a session and adds `LIMIT 1` without fixing concatenation. Impossible uses numeric validation and PDO prepared statements.

The chapter also records the risk of the DVWA database's unsalted MD5 password hashes. The hashes exposed in the lab are intentionally weak and must not be treated as an example of modern password storage.

### 05 - Blind SQL Injection

[05-sqli-blind/README.md](05-sqli-blind/README.md) removes the visible query results and leaves only an "exists" or "missing" response. The walkthrough turns that one-bit signal into a manual proof of concept and an automated character-by-character extraction of the administrator's hash. It adapts the requests for POST input, cookie input, hex-encoded SQL strings, and random response delays.

This chapter shows why hiding database output is not a fix. If attacker-controlled input still reaches SQL syntax, a small reliable signal can be enough to extract sensitive data.

## Vulnerability Comparison

| Vulnerability | DVWA endpoint | Attacker-controlled value | Observable impact in this lab | Strong reference control |
| --- | --- | --- | --- | --- |
| Command Injection | `/vulnerabilities/exec/` | IP address submitted to `ping` | Shell commands run as the web-server user. | Positive IPv4 validation and safe process invocation. |
| CSRF | `/vulnerabilities/csrf/` | Password-change request parameters | An authenticated admin changes their own password without intending to. | Per-session/request token plus current-password re-authentication. |
| File Inclusion | `/vulnerabilities/fi/` | `page` filename/path | Local files and PHP source can be read; included PHP may execute. | Exact allowlist of known filenames. |
| SQL Injection | `/vulnerabilities/sqli/` | User ID in a database query | Rows and password hashes are returned through the response. | PDO prepared statement with a typed parameter. |
| Blind SQL Injection | `/vulnerabilities/sqli_blind/` | User ID in a query with boolean output | Data is extracted through repeated exists/missing questions. | The same prepared-statement and validation model, plus monitoring and rate controls. |

## Concepts Across the Walkthroughs

### Input validation is a server responsibility

Dropdowns, HTML attributes, hidden fields, and JavaScript improve the normal user interface but do not constrain an attacker. A client can modify the page, send a custom request, or use a tool such as `curl` or `requests`. Security decisions must happen on the server.

### Blacklists are brittle

The Medium and High examples repeatedly remove a few known strings or characters. Alternate separators, encoding, wrapper syntax, and small formatting changes survive those filters. A stronger design describes the valid input and rejects everything outside that model.

### Code and data must stay separate

Command injection and SQL injection happen when data is concatenated into an interpreter's program text. Prepared statements solve SQL injection by keeping the query template and parameter values separate. For operating-system commands, prefer a process API that accepts an argument list rather than constructing a shell command.

### Exact allowlists reduce attacker control

The Impossible file-inclusion implementation accepts only four exact filenames. The Impossible command-injection implementation rebuilds an address from validated numeric components. The smaller and more explicit the accepted input space, the less opportunity there is for syntax to acquire a second meaning.

### Authentication cookies do not prove user intent

Browsers attach cookies automatically. A server must distinguish an intentional sensitive action from a request induced by another page. CSRF tokens, appropriate SameSite cookie settings, origin checks, and re-authentication each address part of that problem, while XSS on the same origin can undermine token confidentiality.

### Hiding output does not remove an injection

The blind SQL injection chapter demonstrates that a boolean response is still an information channel. Access control, prepared statements, and authorization must be fixed at the query boundary; suppressing the normal result set is not sufficient.

## How to Read Each Chapter

Most chapters use the same structure:

1. **What the page does** establishes the intended feature and the vulnerable input.
2. **Setup** records the local URL, login state, and configuration assumptions.
3. **Low, Medium, High, Impossible** compare implementation changes and show what each defense does or fails to do.
4. **Form and Source** identify the request shape and the server-side decision point.
5. **Payload, Result, or Verification** connects the request to an observable effect.
6. **Why it works** explains the mechanism rather than treating the payload as magic.
7. **Takeaways** extracts the general defensive lesson.

Read the source-code screenshots alongside the prose. The important question is not only "what payload works?" but also "where does untrusted input cross into a shell, SQL parser, PHP include resolver, or authenticated state-changing action?"

## Reproducing an Exercise

Use this checklist for each security level:

- Confirm the chapter endpoint and local port.
- Confirm the selected DVWA security level.
- Confirm the session belongs to the intended local test account.
- Record the normal request and normal response before changing the input.
- Reproduce the documented request exactly once, then inspect the response and server-side effect.
- Verify sensitive effects through a separate safe check, such as logging in with the resulting test password.
- Reset the database or restore the original value before moving to the next level.
- Read the Impossible implementation and identify the specific boundary that is protected.

For the blind SQL injection examples, use a dedicated lab session cookie and expect repeated requests. The scripts described in the chapter rely on the response text, not on access to a production system or a remote target.

## Troubleshooting

### The DVWA page does not load

Check that DVWA is running and that the URL includes the correct port. The walkthroughs use `127.0.0.1:42001`; a different local port must be substituted in every request and script.

### The payload behaves differently

Confirm the DVWA Security level, the request method, and the input location. Several chapters deliberately change from GET to POST, request parameters to cookies, or request parameters to session-backed popup input.

### The CSRF password test is confusing

CSRF changes persistent state. Reset the database between levels, verify which password is currently active, and log out before testing the replacement password. A stale session or an earlier successful exercise can make a valid result look incorrect.

### The blind SQL injection script fails

Confirm that Python 3 and `requests` are installed, that the PHP session cookie is current, and that the script uses the correct endpoint, security value, request method, and input location for the selected level. High may respond more slowly because the lab intentionally adds random delays.

### Remote file inclusion does not work

That is expected when `allow_url_include` is disabled. The file-inclusion walkthrough documents local file inclusion and stream-wrapper techniques for this configuration instead of assuming remote PHP execution.

### Screenshots do not match the browser

Browser dimensions, installed fonts, DVWA version, PHP version, and security settings can change the exact appearance. Use the screenshots as evidence of the documented run, while treating the request, source behavior, and response text as the primary evidence.

## Defensive Takeaways

- Avoid shell commands when a library or direct system API can perform the task. If a command is unavoidable, validate its structure and pass arguments safely without invoking a shell.
- Use POST for state-changing actions, enforce CSRF protections, configure cookies deliberately, and require re-authentication for high-impact changes.
- Never pass user-controlled paths to `include()` or `require()`. Convert an application-level choice into an exact server-side filename.
- Use prepared statements for every database query that contains external input, with appropriate parameter types.
- Store passwords with modern adaptive password hashing such as Argon2id, bcrypt, or scrypt, with unique salts.
- Treat XSS, CSRF, injection, file disclosure, and weak credential storage as connected risks. Fixing one control does not make the same-origin application trustworthy if another vulnerability can bypass it.

## Project Status

This repository is a documentation and evidence collection for a local DVWA walkthrough. It does not provide a production-ready application, a hardened DVWA fork, or a complete automated scanner. Use the numbered chapters as the detailed source for each exercise and the root README as the navigation, safety, and conceptual guide.
