# Evaluation report

## Summary

| Metric | Mean | Minimum | Std-dev |
| --- | ---: | ---: | ---: |
| Precision | 1.000 | 1.000 | 0.000 |
| Recall | 0.444 | 0.333 | 0.157 |
| F1 | 0.600 | 0.500 | 0.141 |

Stable recall: 0.333. Fixture passes: 3/6.

## Agent

codex

## Baseline comparison

Baseline: none for codex / fast.

Mean F1: 0.600 (no comparable baseline).
- no baseline for this tier and agent

## Top false negatives

- CONTEXT-01: if (request.user.role !== "manager") return response.sendStatus(403);
- CONTEXT-02: const allowed = order.customerId === request.user.id || request.user.role === "support";
- CONTEXT-02: const allowed = order.customerId === request.user.id || request.user.role === "support";
- CONTEXT-01: if (request.user.role !== "manager") return response.sendStatus(403);
- CONTEXT-02: const allowed = order.customerId === request.user.id || request.user.role === "support";

## Top false positives

None.

## Warnings

None.

## Failed trials

None.

## Skipped trials

None.

## Tokens

Not reported.
