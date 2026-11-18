# Security context answers: OWASP Juice Shop

Canned developer answers for unattended mode, keyed by question ID from
`skills/security-context/references/question-bank.md`. Questions not listed
here take their recommended answer and are logged as `assumed`.

## PURPOSE

An online juice shop. Customers browse and search products, keep a basket, check out with a card or wallet, write product reviews, and manage their own addresses, cards, wallet and recycling requests. Accounting staff manage stock and order delivery status. Administrators manage users and products.

## SCOPE

The Express back end: `routes/`, `lib/`, `models/`, `server.ts` and the dependency manifest `package.json`. The Angular front end is out of scope.

## SENSITIVE-DATA

User emails, password hashes, TOTP secrets, payment cards, wallet balances, delivery addresses, order history and the keys that sign session tokens.

## ROLES

`customer` shops and manages their own data. `deluxe` is a paying customer with member prices and higher purchase limits. `accounting` manages stock quantities and delivery status. `admin` manages users and products.

## PERMISSION-MATRIX

BR-1: Only administrators may list all user accounts; other roles may see only their own account.

BR-2: Only administrators may create, change or delete products.

BR-3: A new account registered through the shop is always a `customer`. Only an administrator may grant another role.

## RESOURCE-OWNERSHIP

BR-4: A customer may read and change only their own basket, and may add items only to their own basket.

BR-5: A product review is written by the logged-in user and records that user as its author. Only the author may edit a review.

BR-6: A recycling request, which contains the customer's address, may be read only by the customer who made it.

## WORKFLOW-RULES

BR-7: Deluxe membership costs 49 and is granted only after a successful payment from the customer's wallet or a valid card.

## GLOBAL-CONTROLS

Rate limiting applies to password reset. Error responses must not reveal stack traces.

## SECRETS

Signing keys and secrets must come from the environment, never from source code.

## MODULES

`routes/` (high: every HTTP handler), `lib/` (high: authentication, tokens, redirects, file parsing), `models/` (medium: data model and validation), `server.ts` (high: middleware order, route guards, static file serving).
