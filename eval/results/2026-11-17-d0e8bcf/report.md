# Evaluation report

## Summary

| Metric | Mean | Minimum | Std-dev |
| --- | ---: | ---: | ---: |
| Precision | 0.826 | 0.792 | 0.033 |
| Recall | 0.686 | 0.656 | 0.024 |
| F1 | 0.749 | 0.717 | 0.027 |

Stable recall: 0.459. Fixture passes: 67/84.

## Agent

codex

## Baseline comparison

Baseline: none for codex / full.

Mean F1: 0.749 (no comparable baseline).
- no baseline for this tier and agent

## Top false negatives

- JS-SQLI-SEARCH: name LIKE '%${criteria}%'
- JS-NOSQL-TRACK: $where: `this.orderId === '${id}'`
- JS-NOSQL-REVIEWS: $where: 'this.product == ' + id
- JS-NOSQL-UPDATE: { _id: req.body.id }
- JS-RCE-B2B: vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
- JS-SSRF-IMAGE: const response = await fetch(url)
- JS-LFR-ERASURE: path.resolve(req.body.layout)
- JS-ZIPSLIP: fs.createWriteStream('uploads/complaints/' + fileName)
- JS-FORGED-REVIEW-EDIT: const user = security.authenticatedUsers.from(req)
- JS-FORGED-REVIEW-AUTHOR: author: req.body.author

## Top false positives

- SEC-0002: The q query parameter is interpolated into a Sequelize SQL template literal.
- SEC-0006: The authenticated caller's imageUrl is passed directly to fetch without destination validation.
- SEC-0009: The password hashing helper uses crypto.createHash('md5') with no salt or work factor.
- SEC-0010: A literal HMAC key is supplied directly to crypto.createHmac.
- SEC-0012: The id route parameter is interpolated into a $where JavaScript expression.
- SEC-0013: An archive entry path is concatenated into the write path and the containment condition only checks whether the resolved path contains the current directory.
- SEC-0015: The profile update uses the token cookie but performs no CSRF token or exact Origin/Referer validation.
- SEC-0005: The public /file-upload endpoint accepts an in-memory file before checks that only inspect filename extensions and do not impose a size limit.
- SEC-0009: The checkout handler looks up BasketModel solely by req.params.id and later clears that basket's items without a UserId predicate.
- SEC-0016: hmac constructs a SHA-256 HMAC with a directly assigned secret literal.

## Warnings

None.

## Failed trials

None.

## Skipped trials

None.

## Tokens

Not reported.
