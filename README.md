# API Security Playground

A small, deliberately security-focused system built to learn API authentication and authorization by implementing them end to end and then attacking them. The business logic is intentionally trivial (documents you can create, share, and delete); the point is everything around it: token validation, object- and function-level authorization, CORS, the Backend-for-Frontend pattern, CSRF, and service-to-service security with token exchange and client credentials.

Every defense in this repo has a test or a reproducible demo that tries to break it. The [OWASP mapping](#owasp-api-security-top-10-mapping) below links each risk to that proof.

## Architecture

```
                 ┌──────────────────────────── Keycloak (sandbox realm) ───────────────────────────┐
                 │   authorization code + PKCE      token exchange        client credentials       │
                 └──────▲──────────────────────────────▲──────────────────────────▲───────────────┘
                        │                              │                          │
browser ──(session cookie + CSRF header)──▶ bff ──(Bearer, aud=docs-api)──▶ docs-api ──(Bearer, aud=audit-service)──▶ audit-service
  (no tokens, ever)                    (holds tokens                (resource server +             (append-only resource
                                        server-side)                 OAuth client)                  server)
```

| Service | Role | Port |
|---|---|---|
| `keycloak` | Authorization server. Realm defined as code in `keycloak/realm-export.json`. | 8083 |
| `backend-for-frontend` | OAuth client for the browser. Runs the login flow, keeps tokens in the server-side session, relays `/api/**` to docs-api with the user's token, and serves the test page. | 8081 |
| `docs-api` | Resource server for documents. Also an OAuth client: records every change in audit-service, either on the user's behalf (token exchange) or as itself (a scheduled job using client credentials). | 8082 |
| `audit-service` | Strict, append-only resource server. Accepts writes only from docs-api, takes the actor from the token rather than the request, and has no update or delete endpoints. | <!-- TODO: host port, if exposed --> |

**Stack:** Java, Spring Boot, Spring Security (resource server, OAuth2 client, method security), Keycloak 26.7.4, H2, Docker Compose, JUnit 5, MockMvc, Testcontainers.

## Running it

**Requires:** Docker Desktop.

```bash
docker compose up --build
```

Then open `http://localhost:8081` and log in as one of the seeded users:

| User | Password | Role | Notes |
|---|---|---|---|
| `alice` | `alice` | user | owns most of the seed documents |
| `bob` | `bob` | user | has one of alice's documents shared with him |
| `carol-admin` | `carol` | admin | can reach `/admin/**` |

These are throwaway credentials for a local sandbox, committed on purpose so the project runs with one command.

User IDs are fixed in the realm export (`1111…`, `2222…`, `3333…`), so a token's `sub` stays the same across restarts and the seed data stays valid.

Watch the audit trail as you edit documents:

```bash
docker compose logs -f audit-service
```

Each edit produces a `USER` event naming the acting user, and the scheduled job adds a `SYSTEM_SNAPSHOT` event with no user once a minute.

### Running the tests

```bash
mvn test        # in each service's folder
```

The token-validation suites start a real Keycloak with Testcontainers, so Docker has to be running. The first run pulls the Keycloak image and is slow. The Dockerfiles build with `-DskipTests`, because there's no Docker available inside an image build.

## OWASP API Security Top 10 mapping

Each row is an attack that was actually attempted against this system, and the test or demo that shows it fails.

| Risk | Attack | Defense | Proof |
|---|---|---|---|
| **API1: Broken Object Level Authorization** | bob requests alice's document by ID | Ownership enforced in the query itself. The response is **404, not 403**, so the API doesn't confirm that the document exists. | docs-api `TODO_AuthorizationTestClass`: BOLA tests |
| | bob re-shares a document that was only shared *with* him | Only the owner may share | `bob_cannotReshareDocSharedWithHim` |
| **API2: Broken Authentication** | Tampered payload (`sub` changed to bob), signature reattached | Signature verified against Keycloak's JWKS | docs-api `TokenValidationTest.tamperedPayload_isRejected` |
| | `alg: none` token | Decoder allows `RS256` only; the token's header doesn't choose the algorithm | `TokenValidationTest.algNone_isRejected` |
| | Token signed with the attacker's own key, reusing Keycloak's `kid` | Only keys published by Keycloak are trusted | `TokenValidationTest.signedWithAttackersKey_isRejected` |
| | Genuine token issued for a different API | Audience validator on the custom `JwtDecoder` | `TokenValidationTest.tokenForAnotherAudience_isRejected` |
| | Expired token | `exp` checked against an injectable `Clock` | docs-api `ExpiredTokenTest` |
| | **Replay:** alice's docs-api token sent straight to audit-service | audit-service only accepts `aud=audit-service` | audit-service `ReplayAttackTest.replayedDocsApiToken_isRejected` |
| | Token stolen from the browser via XSS | **BFF pattern:** the browser holds only an `HttpOnly` session cookie; tokens never leave the server | Manual: DevTools shows `JSESSIONID` and `XSRF-TOKEN` and no token anywhere |
| **API3: Broken Object Property Level Authorization** | `ownerId` set in the request body when creating a document | Separate request and response DTOs; the owner always comes from the token | docs-api `create_ignoresOwnerIdInBody` |
| | Audit event forged with `actorUserId` set to bob | Strict request DTO rejects unknown fields with a **400**; the actor comes from the token's `sub` | audit-service `AuditEventSecurityTest.bodyClaimingAnActor_isRejected` |
| **API5: Broken Function Level Authorization** | alice calls the admin endpoint | Role-based rules mapped from Keycloak's `realm_access` | docs-api `regularUser_cannotReachAdminEndpoint` |
| | An admin calls an internal path | Deny by default, even for admins | `internalPaths_areDeniedEvenToAdmins` |
| | A client other than docs-api writes to audit-service | Caller identity checked via `azp`, plus the `audit:write` scope | `AuditEventSecurityTest.callerOtherThanDocsApi_isRejected`, `tokenWithoutAuditScope_isRejected` |
| | A user token records a system event, or a system token records a user event | Caller kind (user vs. system) classified from the token and matched to the action; ambiguous tokens fail closed | `userToken_cannotRecordSystemEvents`, `systemToken_cannotRecordUserEvents`, `ambiguousToken_*` |
| | Updating or deleting audit records | The endpoints don't exist, and every other request is `denyAll()` | `AuditEventSecurityTest`: GET and DELETE tests |
| **API8: Security Misconfiguration** | Cross-origin call from an unlisted origin, method, or header | Explicit CORS allowlist; no wildcards; `allowCredentials(false)` | docs-api `TODO_CorsTestClass` |
| **CSRF** (CWE-352; not in the API Top 10, but relevant once a BFF uses cookies) | Hidden form on an attacker page silently POSTs to the bff | `SameSite=Lax` session cookie, plus a cookie-to-header CSRF token regenerated at login | Manual demo, below |
| **Repudiation** (the "R" in STRIDE) | A user denies an action, or a caller tries to log an action under someone else's name | Append-only audit log; actor taken from the exchanged token; server-set timestamps | `AuditEventSecurityTest` (stored-row assertions) and `ReplayAttackTest` positive controls |

**Not covered:** API4 (resource consumption / rate limiting), API6 (business-flow abuse), API7 (SSRF), API9 (inventory management) and API10 (unsafe consumption of third-party APIs). They were out of scope for an authentication and authorization study.

### How the tests are layered

- **Authorization tests** use Spring Security's `jwt()` post-processor. They're fast and Docker-free, and test the rules: who can do what to which resource.
- **Token-validation tests** send real `Authorization: Bearer` headers with tokens from a real Keycloak in Testcontainers, so the real `JwtDecoder` runs. `jwt()` bypasses the decoder, so it can't test signature, issuer, audience, or expiry.
- **Every attack test checks its own precondition** (for example, that the replayed token really is for `docs-api`), and **every attack suite has positive controls** (for example, a valid token *is* accepted). Without them, a misconfigured test where everything returns 401 would make every attack test pass for the wrong reason.

### The CSRF demo

`attacker/evil.html` auto-submits a hidden form to a form-accepting demo endpoint on the bff. Serve it from a third origin:

```bash
cd attacker
python -m http.server 9000
```

Log in to the bff as alice, open the attacker page in another tab, then look for a document titled **"PWNED via CSRF"**.

| # | Attacker URL | CSRF protection | Result | Why |
|---|---|---|---|---|
| A | `http://127.0.0.1:9000/evil.html` | off | ❌ blocked | Cross-site: `SameSite=Lax` keeps the session cookie off the POST |
| B | `http://localhost:9000/evil.html` | off | ✅ **attack succeeds** | Same-site: the cookie is sent and nothing else checks the request |
| C | `http://localhost:9000/evil.html` | on | ❌ blocked (403) | Cookie sent, but no `X-XSRF-TOKEN` header |

Scenario B is why SameSite alone isn't enough: a sibling origin (a compromised subdomain, for example) counts as same-site. The CSRF switch (`app.demo.csrf-enabled`) exists only for this demo. It has no default, so the bff won't start without an explicit value, and it logs a loud warning whenever protection is off.

## Design decisions worth explaining

- **404 instead of 403 for other users' documents.** A 403 confirms the document exists; a 404 reveals nothing.
- **Token exchange instead of forwarding the user's token.** audit-service requires its own audience, so a docs-api token is useless there (that's the replay test). A compromised audit-service also can't reuse the tokens it receives against docs-api.
- **Client credentials for the scheduled job, not a stored admin token.** The job is the *system*, not a person. A stored admin token would misattribute every snapshot to that admin, grant far more privilege than `audit:write`, keep a powerful long-lived secret around, and break when the admin leaves.
- **Audit calls happen after the transaction commits.** A network call inside the transaction would hold row locks and a pooled database connection for its whole duration, so a slow audit-service could exhaust docs-api's connection pool.
- **Auditing fails open, loudly.** If audit-service is down, the edit still succeeds and docs-api logs the failure. A system that can't lose an audit record would use a **transactional outbox**: write the event to docs-api's own database in the same transaction, and deliver it asynchronously with retries.
- **Unknown fields are rejected, not ignored.** Silently ignoring `actorUserId` hides both forgery attempts and developer mistakes. A 400 surfaces both immediately.
- **Per-user token caching for exchanged tokens.** A single shared cache entry would make every user's edits carry whichever user's token was exchanged first: an audit trail that looks correct and blames the wrong person.
- **The realm is code.** The Keycloak realm is exported to JSON with fixed user IDs and client secrets, so the setup is reproducible and reviewable in a diff.
- **CORS on docs-api is kept as a record of Phase 2.** Since the BFF, no browser calls docs-api directly, so the configuration is no longer needed. <!-- TODO: confirm keep vs. remove -->

## Bugs that taught the most

- **Defining a custom `JwtDecoder` silently dropped the audience check.** Spring Boot's auto-configured decoder backs off, along with the properties it read. The wrong-audience test caught it.
- **Realm drift.** The running Keycloak and `realm-export.json` disagreed more than once (default roles adding an unexpected `account` audience, for example). Fixed in the UI, then re-exported.
- **The token issuer depended on the hostname** Keycloak was reached by (`localhost` from the browser, `keycloak` inside Docker), which breaks token relay. Fixed by configuring Keycloak's hostname rather than working around it in each service.
- **The bff's relay never forwarded request bodies.** It surfaced as `Required request body is missing` on docs-api when sharing a document. The browser had sent the body; the relay dropped it.

## Possible next steps

- A hand-written API-key filter and `AuthenticationProvider`, to work directly with the filter chain
- TOTP or passkeys through Keycloak's built-in flows
- Opaque tokens with introspection instead of JWTs
- mTLS between services
- A transactional outbox for audit events