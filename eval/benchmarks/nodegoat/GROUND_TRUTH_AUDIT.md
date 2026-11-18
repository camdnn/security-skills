# NodeGoat ground-truth audit

## Resolution

Two entries were corrected and a human approved promotion on 2026-11-18. The
reviewed ground truth is now `expected.json` (15 findings).

Audited `expected.draft.json` against repository commit
`c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (the checked-out `repo` HEAD,
matching `benchmark.yaml`). Every evidence line was also checked against
`blank_patterns`: none sits inside a block comment or a whole-line `//`
comment, so all survive comment blanking in the trial copy.

| ID | Status | Audit evidence and conclusion |
| --- | --- | --- |
| NG-SSJS-EVAL | verified | `app/routes/contributions.js:32-34` passes `req.body.preTax`, `afterTax` and `roth` to `eval`. CWE-94 is correct. |
| NG-NOSQL-WHERE | verified | `app/data/allocations-dao.js:77-79` interpolates the `threshold` query value into a `$where` string; the parsing fix at `70-75` is commented out. CWE-943 is correct. |
| NG-IDOR-ALLOCATIONS | verified | `app/routes/allocations.js:16-18` takes `userId` from `req.params` (route `/allocations/:userId`, `index.js:63`); the session-based fix is commented out. CWE-639 and `requires_context: true` (BR-2) fit. |
| NG-BENEFITS-ADMIN | verified | `app/routes/index.js:55-56` guards `/benefits` with `isLoggedIn` only; the `isAdmin` variant is commented out at `57-60`. `benefits-dao.js` lists all non-admin users and updates any user's start date. CWE-862 and `requires_context: true` (BR-1) fit. |
| NG-OPEN-REDIRECT | verified | `app/routes/index.js:70-73` calls `res.redirect(req.query.url)`. CWE-601 is correct. |
| NG-SSRF | verified | `app/routes/research.js:15-16` builds a URL from `req.query.url` and `req.query.symbol`, fetches it with `needle.get`, and writes the body to the response (`24-25`). CWE-918 is correct. |
| NG-PLAINTEXT-PASSWORD | verified | `app/data/user-dao.js:20-25` stores the raw password; `60-61` compares with `===`. The bcrypt fixes are commented out. CWE-916 is correct. |
| NG-SSN-CLEARTEXT | verified | `app/data/profile-dao.js:61-66` stores `ssn` and `dob` as given; the encryption fix at `67-75` is commented out. CWE-311 is correct. |
| NG-HARDCODED-SECRETS | needs revision (applied) | `config/env/all.js:8` hard-codes `cookieSecret`, used by `server.js:82`. The draft also claimed `cryptoKey` (line 9), but every use of it (`profile-dao.js:20-39`) is commented out. Location narrowed to line 8 and the description limited to the cookie secret. |
| NG-SESSION-COOKIE | needs revision (applied) | `server.js:78-102` configures `express-session` without a `cookie` option or `key`. The draft said the cookie lacks httpOnly, but express-session defaults `httpOnly: true`. Description changed to the missing `secure` flag and the default `connect.sid` name. CWE-614 still fits. |
| NG-NO-CSRF | verified | No CSRF middleware is active in `server.js:71-113`; `csurf` is installed but its use at `104-113` is commented out. CWE-352 is correct. |
| NG-XSS-AUTOESCAPE | verified | `server.js:135-137` sets swig `autoescape: false` globally. CWE-79 is correct. |
| NG-SESSION-FIXATION | verified | `app/routes/session.js:116` assigns `req.session.userId` without `req.session.regenerate`. CWE-384 is correct. |
| NG-LOG-INJECTION | verified | `app/routes/session.js:64` logs the raw `userName` from the request body. CWE-117 is correct. |
| NG-DEP-MARKED | verified | `package.json:17` pins `marked` to `0.3.5`, which renders memos (`app/views/memos.html:31`). Versions below 0.3.6 have a sanitizer bypass (CVE-2016-10531, XSS via `data:` URIs with `sanitize: true`). CWE-1104 is correct. |

## Real issues not in this ground truth

These are documented NodeGoat vulnerabilities that live code supports but the
draft did not include. A scan that reports them correctly scores a false
positive, so precision on this benchmark is a lower bound. Adding them is a
separate ground-truth change.

- ReDoS: `app/routes/profile.js:59`, `/([0-9]+)+\#/` on `bankRouting` (CWE-1333).
- Weak password policy: `app/routes/session.js:144`, `PASS_RE = /^.{1,20}$/` (CWE-521).
- Username enumeration: `app/routes/session.js:60-61,85,94`, distinct invalid-user and invalid-password messages (CWE-204).
- Cleartext transport: `server.js:145`, `http.createServer` with the HTTPS block commented out (CWE-319).
- Missing security headers: `server.js:38-65`, the helmet block is commented out and `x-powered-by` stays enabled (CWE-693).

## Checks performed

- `repo` HEAD is `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`; the working tree was clean.
- `python -m eval check-truth` passes after the edits.
