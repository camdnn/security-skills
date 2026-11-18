# Juice Shop ground-truth audit

## Resolution

The seven required corrections were applied, the unsupported cookie-secret
entry was removed, and a human approved promotion on 2026-11-17. The reviewed
ground truth is now `expected.json` (28 findings).

Audited `expected.draft.json` against repository commit
`266448aba68cd8ba5915f526a128da4fa7bc3f9f` (the checked-out `repo` HEAD).
`verified` means the stated source-to-sink/authorization dataflow and CWE are
supported by this checkout. `needs revision` means the underlying issue is
real or plausible, but the draft's location, reachability, or description must
be corrected before promotion. No entries were indeterminate.

| ID | Status | Audit evidence and conclusion |
| --- | --- | --- |
| JS-SQLI-LOGIN | verified | `routes/login.ts:32-35` sends request `email` and MD5(password) through a template literal to Sequelize raw SQL. CWE-89 and description are accurate. |
| JS-SQLI-SEARCH | verified | `routes/search.ts:20-24` takes `req.query.q` and interpolates it twice into raw SQL. The 200-character truncation is not parameterization; CWE-89 is correct. |
| JS-NOSQL-TRACK | verified | `routes/trackOrder.ts:13-20` derives `id` from the route and concatenates it into MarsDB `$where`; the ordinary branch strips metacharacters but the enabled challenge branch merely truncates. CWE-943 is apt. |
| JS-NOSQL-REVIEWS | verified | `routes/showProductReviews.ts:28-38` normally coerces the path value to `Number`, but the enabled challenge path retains a truncated string and concatenates it into `$where`. The contextual enablement should be mentioned, but CWE-943/dataflow are correct. |
| JS-NOSQL-UPDATE | verified | `routes/updateProductReviews.ts:15-24` passes untyped `req.body.id` as a selector and sets `multi: true`; an operator selector can affect multiple documents. CWE-943 and the description are accurate. |
| JS-RCE-B2B | verified | Auth is required at `server.ts:455-456`; when either RCE challenge is enabled, `routes/b2bOrder.ts:17-24` passes client `orderLinesData` to `notevil` inside a VM context. The intended dangerous evaluator is reachable; CWE-94 is appropriate. |
| JS-RCE-PROFILE | verified | Authenticated profile update persists `req.body.username` at `routes/updateUserProfile.ts:15-42`; profile rendering extracts `#{...}` and calls `eval` at `routes/userProfile.ts:52-66` when the challenge is enabled. CWE-94 is correct (the draft's line range contains the sink). |
| JS-SSRF-IMAGE | verified | `routes/profileImageUrlUpload.ts:16-32` takes `req.body.imageUrl`, checks only that a user is logged in, and server-side `fetch`es it. CWE-918 and description are accurate. |
| JS-REDIRECT | verified | `lib/insecurity.ts:121-139` approves any URL containing an allowlisted substring; `routes/redirect.ts:12-21` redirects to that same input. CWE-601 and both locations are correct. |
| JS-LFR-ERASURE | verified | The authenticated data-erasure POST accepts `layout` at `routes/dataErasure.ts:74-80`, attempts only a substring denylist at `103-106`, and spreads the value into `res.render` at `107-118`. The repository's executable test demonstrates `layout=../package.json` reads the file at `test/api/erasure-request.test.ts:92-116`. CWE-22 is correct. |
| JS-ZIPSLIP | verified | `routes/fileUpload.ts:27-36` derives an archive entry path, uses a weak `absolutePath.includes(path.resolve('.'))` check, then writes the original entry path. Traversal can remain inside the checkout and escape `uploads/complaints`; CWE-22 is correct. |
| JS-XXE | verified | `lib/xml.ts:15-41` registers host filesystem providers and enables `XML_PARSE_NOENT` and `XML_PARSE_DTDLOAD`; uploaded XML reaches it at `routes/fileUpload.ts:71-96`. CWE-611 and the two-location dataflow are correct. |
| JS-FORGED-REVIEW-EDIT | verified | PATCH is authenticated at `server.ts:672-675`, but `routes/updateProductReviews.ts:15-24` selects only by caller-provided review id and never compares `author` with the authenticated user. CWE-639 and `requires_context: true` fit. |
| JS-FORGED-REVIEW-AUTHOR | needs revision | `routes/createProductReviews.ts:14-30` writes `req.body.author` without binding it to `user`; the route has no auth middleware (`server.ts:672-675`). Keep CWE-639, but say **any caller, including an unauthenticated caller**, can forge an author; do not imply authentication is required. |
| JS-BASKET-IDOR | verified | Auth is enforced at `server.ts:430-432`; `routes/basket.ts:15-32` queries by path basket id and merely records the ownership mismatch for challenge scoring. It returns the basket without an owner predicate. CWE-639/context flag are correct. |
| JS-BASKET-HPP | verified | Auth is enforced at `server.ts:387-391,457-459`; `routes/basketItems.ts:19-50` validates the first duplicate `BasketId` but saves the last. This is a real parameter-pollution authorization bypass; CWE-639/context flag fit. |
| JS-RECYCLE-IDOR | needs revision | The unauthenticated route is explicit at `server.ts:416-422`; `routes/recycles.ts:11-20` selects by JSON-parsed id with no ownership check. CWE-639 remains defensible, but the response contains `AddressId`, not the joined address fields (`models/recycle.ts:19-24`, `models/relations.ts:110-122`): remove “with addresses” or say “with address identifiers.” Add `server.ts:420` to the truth locations to substantiate the unauthenticated claim. |
| JS-USER-LIST | needs revision | `server.ts:430,634-641` requires an authenticated JWT, while `routes/authenticatedUsers.ts:10-31` returns every user data record, role, and derived last-login timestamp (password/TOTP are masked at `24-28`). The exposure is real and CWE-862 is plausible, but “listing users is an admin function” is an unstated policy assertion; describe the observed overbroad authenticated disclosure instead. |
| JS-DELUXE-FREE | verified | `security.appendUserId()` precedes this route at `server.ts:666-669`; `routes/deluxe.ts:16-50` upgrades that customer for any payment mode other than wallet/card, with neither charge nor validation. CWE-863 and contextual classification are correct. |
| JS-ROLE-MASS-ASSIGN | needs revision | The role setter permits `admin` (`models/user.ts:76-95`), but it does not itself read a request. The relevant registration path is unauthenticated `POST /api/Users` at `server.ts:394-454`, and generated Finale resources bind `UserModel` at `server.ts:518-546`; `routes/verify.ts:52-56` confirms `req.body.role === admin` is the challenge flow. Retain CWE-915, but add those locations and change evidence from the setter to the request-to-generated-create path. |
| JS-PRODUCT-PUT | verified | `server.ts:382-403` registers guards before Finale generated endpoints (`518-546`); the Product PUT guard is commented, leaving generated PUT reachable without its intended authorization. CWE-862/context flag and description are accurate. |
| JS-JWT-PRIVATE-KEY | verified | `lib/insecurity.ts:20-21` reads the public key but embeds the RSA private key, and `54-55` use the pair to sign/verify JWTs. CWE-798 is correct. |
| JS-COOKIE-SECRET | needs revision | `server.ts:321` supplies a literal to `cookieParser`, but no source use of `req.signedCookies`/signed-cookie verification exists in this checkout (the only `cookieParser` occurrence is that registration). The literal is poor practice, but the draft establishes no security-relevant signing dataflow. Remove it from truth unless a reachable signed-cookie consumer is identified. |
| JS-MD5-PASSWORD | verified | `lib/insecurity.ts:41` implements bare MD5 and the model password setter stores it at `models/user.ts:70-75`; no salt is supplied. CWE-916 and description are correct. |
| JS-DIR-LISTING | verified | `server.ts:292-308` enables `serveIndex` for `/ftp`, `/encryptionkeys`, and `/support/logs`; adjacent handlers serve files from those directories. CWE-548 and all three listed locations are correct. |
| JS-ERROR-DETAIL | verified | The terminal middleware unconditionally installs `errorhandler()` at `server.ts:720-723` (and sets its title at `772`). That makes detailed development-style error handling reachable irrespective of an environment guard; CWE-209 is appropriate. |
| JS-RATE-LIMIT-XFF | needs revision | `server.ts:374-379` enables `trust proxy` and uses `req.ip` as fallback. Node normalizes request-header keys, so `headers['X-Forwarded-For']` is not the raw header lookup claimed by the draft; nonetheless `trust proxy` makes `req.ip` proxy-header-derived. Keep CWE-307, but cite `374-379` and explain the bypass through trusted proxy/IP derivation, not the capitalized header expression. |
| JS-PASSWORD-CHANGE | verified | `routes/changePassword.ts:12-56` authenticates a token but rejects a current password only when a nonempty value was sent, then updates the account password. CWE-620 and the description are correct. |
| JS-DEP-JSONWEBTOKEN | needs revision | `package.json:93-147` pins `jsonwebtoken` to `0.4.0`, so CWE-1104 is structurally valid. The draft additionally asserts a particular CVE/signature-bypass reachability without local lockfile or dependency implementation evidence; either cite a vetted advisory/reachability analysis or limit the description to the outdated pinned dependency. |

## Checks performed

- Checked `repo` HEAD: `266448aba68cd8ba5915f526a128da4fa7bc3f9f`; working tree was clean.
- `expected.draft.json` passes `eval/schemas/expected.schema.json` (29 unique IDs; all CWEs registered).
- `eval.truth.check_truth_file(...)` passes: all current evidence quotes occur in a declared range. This is only structural/evidence validation; it does not validate the semantic revisions above.

## Promotion recommendation

**Resolved.** The seven must-fix revisions were applied: `JS-FORGED-REVIEW-AUTHOR`, `JS-RECYCLE-IDOR`, `JS-USER-LIST`, `JS-ROLE-MASS-ASSIGN`, `JS-COOKIE-SECRET`, `JS-RATE-LIMIT-XFF`, and `JS-DEP-JSONWEBTOKEN`. `JS-COOKIE-SECRET` was removed because no reachable signed-cookie consumer was found. Schema and truth checks passed after the edits.
