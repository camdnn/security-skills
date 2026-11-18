# Evaluation report

## Summary

| Metric | Mean | Minimum | Std-dev |
| --- | ---: | ---: | ---: |
| Precision | 0.748 | 0.721 | 0.030 |
| Recall | 0.841 | 0.815 | 0.036 |
| F1 | 0.790 | 0.765 | 0.018 |

Stable recall: 0.609. Fixture passes: 69/78.

## Agent

claude

## Baseline comparison

Baseline: none for claude / full.

Mean F1: 0.790 (no comparable baseline).
- no baseline for this tier and agent

## Top false negatives

- JS-NOSQL-UPDATE: { _id: req.body.id }
- JS-BASKET-HPP: BasketId: basketIds[basketIds.length - 1]
- JS-RECYCLE-IDOR: id: JSON.parse(req.params.id)
- JS-USER-LIST: const users = await UserModel.findAll()
- CONTEXT-01: if (request.user.role !== "manager") return response.sendStatus(403);
- CONTEXT-02: const allowed = order.customerId === request.user.id || request.user.role === "support";
- CONTEXT-01: if (request.user.role !== "manager") return response.sendStatus(403);
- CONTEXT-02: const allowed = order.customerId === request.user.id || request.user.role === "support";
- JS-NOSQL-REVIEWS: $where: 'this.product == ' + id
- JS-RCE-B2B: vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })

## Top false positives

- SEC-0005: MemoryModel.findAll({ include: [UserModel] }) returned in res.json; route registered at server.ts:670 with no isAuthorized
- SEC-0006: expressJwt({ secret: publicKey }); jws.verify(token, publicKey); jwt.verify(token, publicKey, cb) at line 189 - no algorithms option
- SEC-0009: req.body.password === '<redacted>' compared for admin@, support@, mc.safesearch@, amy@, J12934@, testing@ and a gmail account
- SEC-0013: app.post('/rest/user/login', login()) with no rateLimit middleware (limiters exist only for reset-password and 2FA)
- SEC-0017: res.json({ config: structuredClone(config.util.toObject(config)) }) at /rest/admin/application-configuration, registered at server.ts:646 without authorization
- SEC-0024: generateCoupon: z85.encode(toMMMYY(date) + '-' + discount); discountFromCoupon decodes and accepts any correctly formatted current-month value
- SEC-0026: "express-jwt": "0.1.3"
- SEC-0033: "sanitize-html": "1.4.2"
- SEC-0034: crypto.createHmac('sha256', '<redacted literal>')
- SEC-0036: WalletModel.increment({ balance: req.body.balance }, { where: { UserId: req.body.UserId } })

## Warnings

None.

## Failed trials

None.

## Skipped trials

None.

## Tokens

Not reported.
