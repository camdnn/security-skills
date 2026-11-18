# Evaluation report

## Summary

| Metric | Mean | Minimum | Std-dev |
| --- | ---: | ---: | ---: |
| Precision | 0.719 | 0.617 | 0.101 |
| Recall | 0.880 | 0.806 | 0.086 |
| F1 | 0.791 | 0.699 | 0.096 |

Stable recall: 0.556. Fixture passes: 5/10.

## Agent

claude

## Baseline comparison

Baseline: none for claude / full.

Mean F1: 0.791 (no comparable baseline).
- no baseline for this tier and agent

## Top false negatives

- PI-SQLI: name LIKE '%${term}%'
- PI-SECRET: const stripeSecretKey = 'sk_live_
- NG-SESSION-COOKIE: secret: cookieSecret,
- NG-XSS-AUTOESCAPE: autoescape: false
- NG-SSN-CLEARTEXT: user.ssn = ssn;
- NG-SESSION-COOKIE: secret: cookieSecret,
- NG-XSS-AUTOESCAPE: autoescape: false
- NG-BENEFITS-ADMIN: app.get("/benefits", isLoggedIn, benefitsHandler.displayBenefits)
- NG-SSN-CLEARTEXT: user.ssn = ssn;
- NG-XSS-AUTOESCAPE: autoescape: false

## Top false positives

- SEC-0001: const stripeSecretKey = 'sk_live_FAKE…' is assigned directly in source and exposed through paymentClient().
- SEC-0003: db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`) concatenates req.query.q into the SQL text.
- SEC-0004: req.query.file is used in uploads/${name} and out/${name}.png with no resolved-path containment check.
- SEC-0004: const name = String(req.query.file)
exec(`convert uploads/${name} out/${name}.png`, ...)
- SEC-0004: memosDAO.insert(req.body.memo, ...) stores raw text; res.render("memos", { memosList: docs }); swig.setDefaults({ autoescape: false }) in server.js:135-137
- SEC-0007: res.writeHead(200, { "Content-Type": "text/html" }); ... res.write(body);
- SEC-0008: handleLoginRequest -> userDAO.validateLogin(userName, password, ...) with no rate limiter or failure counter; none registered in server.js
- SEC-0016: res.status(500); res.render("error-template", { error: err });
- SEC-0018: zapApiKey: "v9dn0balpq..." (redacted)
- SEC-0019: zapApiKey: "v9dn0balpq..." (redacted)

## Warnings

None.

## Failed trials

- nodegoat-context-2: [Errno 2] No such file or directory: '/tmp/eval-trial-qwijf5o3/target/docs/security/findings.json'
- nodegoat-code-only-2: [Errno 2] No such file or directory: '/tmp/eval-trial-bsp9pyqu/target/docs/security/findings.json'

## Skipped trials

None.

## Tokens

Not reported.
