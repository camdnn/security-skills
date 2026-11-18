# Decision record template

Write `docs/security/decisions/NNN-<slug>.md` only for a security decision
that is hard to reverse **and** surprising **and** a real trade-off (for
example, "admins may read customer invoices for chargeback disputes"). Keep it
to **about 40 lines**. Number decisions from `001` in the order recorded.

---

```markdown
# NNN: <decision in a few words>

Date: <YYYY-MM-DD> · Source: <question ID or "code"> · Status: <accepted | questioned>

## Decision

<One or two sentences.>

## Why

<The trade-off the team accepted.>

## Consequences for scanning

<Which findings this decision explains or rules out, citing BR-n where relevant.>
```
