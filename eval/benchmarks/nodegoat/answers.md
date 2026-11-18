# Security context answers: OWASP NodeGoat

Canned developer answers for unattended mode, keyed by question ID from
`skills/security-context/references/question-bank.md`. Questions not listed
here take their recommended answer and are logged as `assumed`.

## PURPOSE

A retirement-savings portal. Employees sign up, manage their profile (including SSN, date of birth and bank details), set contribution percentages, view their asset allocations, post memos and research stocks. Administrators manage employees' benefit start dates.

## SCOPE

The Express server: `app/routes/`, `app/data/`, `config/`, `server.js` and `package.json`. Templates and front-end assets are out of scope.

## SENSITIVE-DATA

Passwords, SSNs, dates of birth, bank account and routing numbers, contribution and allocation data.

## ROLES

`employee` manages their own retirement account. `admin` (a user with `isAdmin`) manages benefits for all employees.

## PERMISSION-MATRIX

BR-1: Only administrators may view or change employees' benefit start dates.

## RESOURCE-OWNERSHIP

BR-2: An employee may view only their own allocations, profile and contributions.

## WORKFLOW-RULES

BR-3: Contribution percentages are numbers from 0 to 30 in total.

## SECRETS

The session secret and crypto key must come from the environment.

## MODULES

`app/routes/` (high: HTTP handlers and authorization), `app/data/` (high: database access, credentials, sensitive data), `config/` (medium: secrets and settings), `server.js` (high: middleware, session and template configuration).
