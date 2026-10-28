# Security Analyzer

A Claude plugin of security skills that finds, explains, ranks and optionally fixes vulnerabilities in Node/TS + Express codebases, plus a checker that measures how accurately it does so.

## Findings

**Finding**:
One vulnerability reported by the plugin, with location, evidence, trace and DREAD score.
_Avoid_: Issue, alert, result

**Pre-finding**:
A mismatch between the developer's stated intent and the code, noticed while building context, before any scan.
_Avoid_: Early finding, hint

**Mode**:
Whether a scan had pre-built context available: **context** or **code-only**.
_Avoid_: Using "mode" for anything else (see Unattended mode)

**Unattended mode**:
Context-building that reads canned interview answers instead of asking the developer; any unanswered question takes its recommended answer and is recorded as assumed.
_Avoid_: Eval mode, headless mode, batch mode

## Context

**Module**:
A slice of the target codebase described by its own context file, with entry points, business rules and a contract.
_Avoid_: Component, package, area

**Business rule**:
A statement of intended behaviour (e.g. "users see only their own orders"), identified as `BR-n`, that a finding can cite.
_Avoid_: Requirement, policy

**Contract**:
What a module ASSUMES of its callers and GUARANTEES to them.
_Avoid_: Interface, spec

**Stale module**:
A module whose covered paths changed since the commit its context was built from.
_Avoid_: Outdated module

## Evaluation

**Target**:
A codebase the checker scans: either a fixture or a benchmark.
_Avoid_: Project, app, test case

**Fixture**:
A tiny hand-written target built to exercise one check; **vulnerable** fixtures hold one vulnerability per file, **safe** fixtures hold look-alike code that must produce no findings.
_Avoid_: Sample, test app

**Benchmark**:
A real, intentionally vulnerable application pinned at a specific commit.
_Avoid_: Test repo, corpus

**Ground truth**:
The hand-verified set of truth entries and must-not-find rules for a target. Changed only on purpose, never to make a score pass.
_Avoid_: Expected results, answers, labels

**Truth entry**:
One real vulnerability in ground truth, with one or more acceptable locations and a quote of the vulnerable code that must exist at those locations.
_Avoid_: Expected finding, label

**Requires-context entry**:
A truth entry for a business-logic flaw that can only be detected with context; its recall is reported separately.
_Avoid_: Logic bug, context bug

**Must-not-find rule**:
A ground-truth statement that no finding of a given CWE family may appear in a given safe file.
_Avoid_: Negative label, exclusion

**CWE family**:
A group of related CWEs treated as the same kind of vulnerability for matching (e.g. SQL, OS-command and code injection form the injection family).
_Avoid_: Category, class

**Owning check**:
The single check skill responsible for a CWE family; misses in that family are attributed to it.
_Avoid_: Responsible skill

**Match**:
A one-to-one pairing of a finding with a truth entry: same file, overlapping lines within tolerance, same CWE family.

**Duplicate**:
A finding that would have matched a truth entry already matched by another finding. Counted separately, not as a false positive.
_Avoid_: Repeat, double

## Runs

**Eval run**:
One invocation of the checker over a tier, producing one report.
_Avoid_: Run (unqualified), job

**Agent**:
The coding assistant that executes a trial: Claude Code or Codex. Each eval run records which one it used.
_Avoid_: Backend, provider, model

**Trial**:
One scan of one target in one mode within an eval run; an eval run repeats each target × mode several times.
_Avoid_: Run, attempt, iteration

**Failed trial**:
A trial whose output is invalid against the finding schema, or which changed files outside the target's security docs folder.
_Avoid_: Crashed run

**Skipped trial**:
A trial not executed because the trial cap or the agent's usage limit was reached.
_Avoid_: Failed trial

**Incomplete eval run**:
An eval run with skipped trials. It can be resumed, but it is never compared against or accepted as a baseline.
_Avoid_: Partial run

**Tier**:
Which targets an eval run covers: **fast** (fixtures only) or **full** (fixtures and benchmarks, both modes).

**Fixture pass**:
A vulnerable fixture passes a trial when every truth entry is matched; a safe fixture passes when no must-not-find rule is hit.

**Stable recall**:
The share of truth entries matched in every trial of an eval run.

**Baseline**:
The last deliberately accepted metrics for a tier, recording which agent produced them. Later eval runs are compared against it only when they used the same agent.
_Avoid_: Reference, golden

**Regression**:
A mean F1 drop larger than the threshold versus the baseline, or a fixture that passed in most baseline trials and now passes in none.

**Ablation**:
An eval run with one context technique turned off, to measure that technique's effect.
