# Security-context question bank

Ask these in order only when the answer cannot be derived from code. Record the
recommended answer, actual or assumed answer, source, and date in `ANSWERS.md`.

1. **What is the application's security-relevant purpose?**
   - Derive from routes, package metadata, and user-facing documentation.
   - Recommended answer: name the protected assets and the intended users.
2. **Which roles exist, and which actions may each role perform?**
   - Derive from authentication middleware, role checks, and route handlers.
   - Recommended answer: least privilege; deny an action unless a role is explicitly allowed.
3. **What ownership rules apply to records?**
   - Derive from identifiers in routes and data access queries.
   - Recommended answer: a user may access only records they own unless a documented privileged role is required.
4. **Which actions require a separate approval or segregation of duties?**
   - Derive from state transitions, audit events, and terms such as approve, refund, publish, or pay.
   - Recommended answer: requesters cannot approve their own sensitive action.
5. **Which data is confidential, regulated, or secret?**
   - Derive from schema names, environment variables, and external integrations.
   - Recommended answer: treat credentials, tokens, payment data, and personal data as confidential.
6. **Which external systems and trust boundaries are involved?**
   - Derive from HTTP clients, queues, storage SDKs, and callback routes.
   - Recommended answer: validate untrusted input at each boundary and authenticate callbacks.
7. **What is the expected behavior on authorization or validation failure?**
   - Derive from error handling and middleware.
   - Recommended answer: fail closed, return a non-sensitive error, and audit sensitive actions.
