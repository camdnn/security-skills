# Metrics are micro-averaged across targets

Precision, recall and F1 for each trial are computed once, from TP/FP/FN summed over every target in the tier. They are not the mean of per-target scores. A clean safe fixture (0 TP, 0 FP, 0 FN) is a perfect result, but per-target averaging would score it as precision 0 with undefined recall and punish correct behaviour. When TP+FP = 0, per-target precision is reported as `null`, not 0.

## Consequences

Baselines recorded under this rule can't be compared with macro-averaged numbers. Switching methods later means re-accepting every baseline.
