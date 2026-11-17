# Evaluation report

## Summary

| Metric | Mean | Minimum | Std-dev |
| --- | ---: | ---: | ---: |
| Precision | 0.845 | 0.765 | 0.071 |
| Recall | 0.956 | 0.867 | 0.063 |
| F1 | 0.896 | 0.812 | 0.064 |

Stable recall: 0.867. Fixture passes: 31/33.

## Agent

claude

## Baseline comparison

Baseline: claude / fast.

Mean F1: 0.896 (▼ -0.070 vs baseline).
- mean F1 dropped by 0.070, exceeding threshold 0.050

## Top false negatives

- ACCESS-01: const account = await accounts.findById(request.params.userId);
- CRYPTO-01: Math.random()

## Top false positives

- SEC-0001: const account = await accounts.findById(request.params.userId);
  response.json(account);
- SEC-0003: if (!order) return response.sendStatus(404); const allowed = ...; if (!allowed) return response.sendStatus(403);
- SEC-0003: response.json(await refunds.approve(refund.id, request.user.id));
- SEC-0004: if (order.status !== "placed") return response.sendStatus(409);
response.json(await orders.cancel(order.id));
- SEC-0005: if (!refund || refund.status !== "requested") return response.sendStatus(404);
response.json(await refunds.approve(refund.id, request.user.id));
- SEC-0003: response.json(await refunds.approve(refund.id, request.user.id));
- SEC-0004: if (order.status !== "placed") return response.sendStatus(409); response.json(await orders.cancel(order.id));
- SEC-0001: export function resetToken() { return Math.random().toString(36).slice(2); }

## Warnings

None.

## Failed trials

None.

## Skipped trials

None.

## Tokens

Not reported.
