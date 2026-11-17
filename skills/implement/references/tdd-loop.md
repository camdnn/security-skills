# TDD loop rules

Rules for each finding `implement` fixes. A fix counts only when every step
below is proven by running the tests, not by reading the code.

## RED

- Write a **new** test; do not repurpose an existing one.
- Drive the vulnerable path through the public interface with an attacker-style
  input: a SQL fragment, `../` in a path, another user's id, a missing secret.
- Run it and see it fail **for the security reason**. A syntax error, a missing
  import or a wrong assertion is not RED: fix the test and run it again.
- Keep the test deterministic and offline: no network, no real credentials, no
  sleeping on timing.

## GREEN

- Make the smallest change that removes the flaw: parameterize the query,
  contain the path, check ownership, read the secret from the environment.
- Change only what the finding needs. No drive-by refactors or upgrades.
- Run the new test and see it pass.

## REFACTOR

- Tidy only the code you touched, keeping every test green.

## VERIFY

- Run the **full** suite. Every existing test must still pass unmodified.
- Re-apply the finding's owning check to the changed files: the finding is
  gone, and no new finding appears.
- If the fix breaks behaviour an existing test describes, the fix is wrong, not
  the test. Rework it or log the finding as `needs-human`.

## Untestable → needs human

Log the finding as `needs-human`, change no code for it, and say why when:

- the fix needs the network or a package install (dependency upgrades);
- the flaw lives in deployment, infrastructure or configuration the tests
  cannot load;
- the fix needs a product or business decision (who should be allowed to do
  what);
- no test can reach the vulnerable path without running external services.

A `needs-human` finding is a correct outcome. An untested "fix" is not.
