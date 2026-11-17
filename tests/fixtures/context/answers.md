# Security context answers

Canned developer answers for unattended mode, keyed by question ID from
`skills/security-context/references/question-bank.md`. Questions not listed
here take their recommended answer and are logged as `assumed`.

## PURPOSE

An order service: customers place and cancel orders and download invoices; support staff help customers with their orders; managers approve refunds.

## ROLES

`customer` places orders. `support` helps customers with their orders. `manager` approves refunds.

## RESOURCE-OWNERSHIP

BR-2: Only the customer who placed an order may download its invoice. Support staff may not download invoice PDFs, because invoices contain payment details.

BR-3: A customer may cancel only their own order while it is placed; support may cancel any placed order for support purposes.

## SEPARATION-OF-DUTIES

BR-1: A manager may approve a refund only if someone else requested it. The requester and the approver must be different people.
