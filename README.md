# API Security Playground

![CI](https://github.com/<!-- TODO: owner -->/API-security-sandbox/actions/workflows/ci.yml/badge.svg)

A small, deliberately security-focused system built to learn API authentication and authorization by implementing them end to end and then attacking them. The business logic is intentionally trivial (documents you can create, share, and delete); the point is everything around it: token validation, object- and function-level authorization, CORS, the Backend-for-Frontend pattern, CSRF, service-to-service security with token exchange and client credentials, a hand-written API-key authentication mechanism, rate limiting, identity-provider hardening, and a locked-down CI pipeline.

Every defense in this repo has a test or a reproducible demo that tries to break it. The [OWASP mapping](#owasp-api-security-top-10-mapping) below links each risk to that proof.

## Architecture

```
                 ┌──────────────────────────── Keycloak (sandbox realm) ───────────────────────────┐
                 │   authorization code + PKCE      token exchange        client credentials       │
                 └──────▲──────────────────────────────▲──────────────────────────▲───────────────┘
                        │                              │                          │
browser ──(session cookie + CSRF header)──▶ bff ──(Bearer, aud=docs-api)──▶ docs-api ──(Bearer, aud=audit-service)──▶ audit-service
  (no tokens, ever)                    (holds tokens   │            (resource server +             (append-only resource
                                        server-side)   │             OAuth client)                  server)
                                                       ▼                    ▲
                                              Redis (rate-limit        machine caller ──(X-API-Key)──▶ /internal/**
                                                     buckets)          (not in Keycloak)
```

| Service | Role | Port |
|---|---|---|
| `keycloak` | Authorization server. Realm defined as code in `keycloak/realm-export.json`, including brute-force detection and login-event settings. | 8083 |
| `backend-for-frontend` | OAuth client for the browser. Runs the login flow, keeps tokens in the server-side session, relays `/api/**` to docs-api with the user's token, rate-limits every caller, and serves the test page. | 8081 |
| `docs-api` | Resource server for documents. Also an OAuth client: records every change in audit-service, either on the user's behalf (token exchange) or as itself (a scheduled job using client credentials). Exposes a separate `/internal/**` API for machine callers that authenticate with API keys. | 8082 |
| `audit-service` | Strict, append-only resource server. Accepts writes only from docs-api, takes the actor from the token rather than the request, and has no update or delete endpoints. | <!-- TODO: host port, if exposed --> |
| `redis` | Shared, atomic state for the bff's rate-limit buckets. | 6379 |

**Stack:** Java 25, Spring Boot 4, Spring Security (resource server, OAuth2 client, method security, a custom `AuthenticationProvider`), Keycloak 26.7.4, Bucket4j, Redis, H2, Docker Compose, JUnit 5, MockMvc, Testcontainers, GitHub Actions.

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
| `lockout-target` | `lockout-target-password` | user | **reserved for the brute-force test**; don't use it for anything else |

These are throwaway credentials for a local sandbox, committed on purpose so the project runs with one command. The same goes for the test client secrets and the dev API keys below: they only ever touch a throwaway Keycloak and an in-memory database, so the CI pipeline needs no secrets at all.

User IDs are fixed in the realm export (`1111…`, `2222…`, `3333…`), so a token's `sub` stays the same across restarts and the seed data stays valid.

Watch the audit trail as you edit documents:

```bash
docker compose logs -f audit-service
```

Each edit produces a `USER` event naming the acting user, and the scheduled job adds a `SYSTEM_SNAPSHOT` event with no user once a minute.

Failed logins show up in Keycloak's log as login events:

```bash
docker compose logs -f keycloak
```

### Calling the internal API with an API key

docs-api seeds three dev keys from `apikeys.dev.*` in its `application.yml`: one active, one revoked and one expired.

```bash
curl -H "X-API-Key: <the active dev key>" http://localhost:8082/internal/reports/summary
```

The active key returns a document count and the caller's name (`reporting-tool`). The revoked and expired keys, a wrong secret, a malformed key and a missing header all get the same empty `401`.

### Seeing the rate limiter

Unauthenticated requests spend the IP tier's tokens:

```powershell
1..110 | % { curl.exe -s -o NUL -w "%{http_code}`n" http://localhost:8081/me }
```

The output is `401`s from Spring Security until the bucket is empty, then `429`s with a `Retry-After` header. Stop Redis (`docker compose stop redis`) and the requests go back to `401`: the limiter fails open, with a warning in the bff's log.

If you change `realm-export.json`, recreate Keycloak so the realm is re-imported: `docker compose up -d --force-recreate keycloak`. `--import-realm` skips realms that already exist.

### Running the tests

```bash
mvn test        # in each service's folder
```

docs-api's token-validation and brute-force suites start a real Keycloak with Testcontainers, and the bff's rate-limit suites start a real Redis, so Docker has to be running. The first run pulls the images and is slow. The Dockerfiles build with `-DskipTests`, because there's no Docker available inside an image build.

### CI

`.github/workflows/ci.yml` builds and tests all three services in parallel on every push to `main` and every pull request. Branch protection on `main` requires all three checks to pass, with no bypass list. See [CI and supply chain](#ci-and-supply-chain).

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
| | Password guessing against a known account | Keycloak brute-force detection: 25 failures trigger a growing temporary lockout, and the fourth lockout is permanent | docs-api `BruteForceLockoutTest`: after 25 spaced wrong passwords, the *correct* password is refused, and Keycloak's attack-detection status confirms why |
| | Revoked, expired, wrong-secret, unknown or malformed API key | Hand-written provider checks the secret, then revocation and expiry; every failure is the same empty `401` | docs-api `ApiKeyAuthenticationIntegrationTest.badKeys_allGetTheSameEmpty401` (one case per provider branch) |
| | Stolen API-key database | Only SHA-256 hashes are stored; comparison is constant-time | `ApiKeysTest` (against the published SHA-256 test vector) |
| **API3: Broken Object Property Level Authorization** | `ownerId` set in the request body when creating a document | Separate request and response DTOs; the owner always comes from the token | docs-api `create_ignoresOwnerIdInBody` |
| | Audit event forged with `actorUserId` set to bob | Strict request DTO rejects unknown fields with a **400**; the actor comes from the token's `sub` | audit-service `AuditEventSecurityTest.bodyClaimingAnActor_isRejected` |
| **API4: Unrestricted Resource Consumption** | Unauthenticated flood, including login starts that each create a server-side session | IP-keyed token bucket in a servlet filter that runs **before** Spring Security | bff `IpRateLimitTest`: the 401s turn into 429s once the bucket is empty, and a limited login request creates no session |
| | A logged-in user (or script) hammering the API | `sub`-keyed token bucket in an MVC interceptor; writes cost more than reads; limited requests are rejected before they're relayed to docs-api | bff `UserRateLimitTest` (exact token arithmetic, per-user isolation, and requests rejected by security cost nothing) |
| | Taking Redis down to break the site | Fails open at runtime: limiting stops, the site keeps working, and a warning is logged | bff `RateLimitFailOpenTest`, with a positive control that the limit *was* enforced first |
| **API5: Broken Function Level Authorization** | alice calls the admin endpoint | Role-based rules mapped from Keycloak's `realm_access` | docs-api `regularUser_cannotReachAdminEndpoint` |
| | A user's JWT, even an admin's, sent to `/internal/**` | `/internal/**` is a separate filter chain that only understands API keys; the bearer token is never read | `internalPaths_areDeniedEvenToAdmins`, `ApiKeyAuthenticationIntegrationTest.bearerTokenOnInternalPath_isIgnoredByTheApiKeyChain` |
| | A valid API key used on a normal document endpoint, or on an unlisted internal path | Each chain ignores the other's mechanism; inside `/internal/**`, anything not explicitly allowed is `denyAll()` | `apiKeyOnDocumentsEndpoint_isIgnoredByTheJwtChain`, `validKeyOnUnlistedInternalPath_isForbidden` |
| | A client other than docs-api writes to audit-service | Caller identity checked via `azp`, plus the `audit:write` scope | `AuditEventSecurityTest.callerOtherThanDocsApi_isRejected`, `tokenWithoutAuditScope_isRejected` |
| | A user token records a system event, or a system token records a user event | Caller kind (user vs. system) classified from the token and matched to the action; ambiguous tokens fail closed | `userToken_cannotRecordSystemEvents`, `systemToken_cannotRecordUserEvents`, `ambiguousToken_*` |
| | Updating or deleting audit records | The endpoints don't exist, and every other request is `denyAll()` | `AuditEventSecurityTest`: GET and DELETE tests |
| **API8: Security Misconfiguration** | Cross-origin call from an unlisted origin, method, or header | Explicit CORS allowlist; no wildcards; `allowCredentials(false)` | docs-api `TODO_CorsTestClass` |
| | Brute-force settings edited in the admin console but never committed | Realm-as-code; the test suite checks the imported realm before attacking it | `BruteForceLockoutTest.realmHasBruteForceProtectionConfigured` |
| **CSRF** (CWE-352; not in the API Top 10, but relevant once a BFF uses cookies) | Hidden form on an attacker page silently POSTs to the bff | `SameSite=Lax` session cookie, plus a cookie-to-header CSRF token regenerated at login | Manual demo, below |
| **Repudiation** (the "R" in STRIDE) | A user denies an action, or a caller tries to log an action under someone else's name | Append-only audit log; actor taken from the exchanged token; server-set timestamps; Keycloak login events record the authentication side | `AuditEventSecurityTest` (stored-row assertions) and `ReplayAttackTest` positive controls |

**Not covered:** API6 (business-flow abuse), API7 (SSRF), API9 (inventory management) and API10 (unsafe consumption of third-party APIs). They were out of scope for an authentication and authorization study.

### Known gaps

Deliberate limits, so they read as choices rather than oversights:

- **Password spraying.** Brute-force detection counts failures per user, so one common password tried once against many accounts never trips it. The fixes live outside this repo: per-IP limits in front of Keycloak (a reverse proxy or WAF), and MFA or passkeys so a guessed password isn't enough. Password submissions go from the browser straight to Keycloak, so the bff's rate limiter never sees them.
- **API-key callers aren't rate-limited.** They call docs-api directly, not through the bff. In production, docs-api wouldn't be publicly reachable; network isolation is the real control there.
- **docs-api accepts any client with the `docs-api` audience.** An `azp` allowlist (as audit-service has) would add a second check against Keycloak misconfiguration. audit-service already demonstrates the pattern.
- **Admin events are off.** Keycloak's admin events would record who changed which client, scope or role. They're the control that would catch realm configuration drift.
- **Redis has no password.** Anyone who can reach it can reset their own buckets. In production it would sit on a private network with authentication.

### How the tests are layered

- **Authorization tests** use Spring Security's `jwt()` post-processor. They're fast and Docker-free, and test the rules: who can do what to which resource.
- **Token-validation tests** send real `Authorization: Bearer` headers with tokens from a real Keycloak in Testcontainers, so the real `JwtDecoder` runs. `jwt()` bypasses the decoder, so it can't test signature, issuer, audience, or expiry.
- **Chain-isolation tests** send real headers too, and use the `WWW-Authenticate` header to prove *which* filter chain answered: the JWT chain's entry point adds `WWW-Authenticate: Bearer`, the API-key chain's doesn't.
- **The brute-force test** talks to Keycloak directly, with no Spring context: the thing under test is the realm, not docs-api.
- **Rate-limit tests** run against a real Redis in Testcontainers with tiny test-only limits. Every test uses its own IP or user, so buckets left behind by other tests can't interfere.
- **Every attack test checks its own precondition** (for example, that the replayed token really is for `docs-api`), and **every attack suite has positive controls** (for example, a valid token *is* accepted, the seeded user *can* log in before the lockout, the limit *is* enforced before Redis goes down). Without them, a misconfigured test where everything returns 401 would make every attack test pass for the wrong reason.

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

### Users, tokens and services

- **404 instead of 403 for other users' documents.** A 403 confirms the document exists; a 404 reveals nothing.
- **Token exchange instead of forwarding the user's token.** audit-service requires its own audience, so a docs-api token is useless there (that's the replay test). A compromised audit-service also can't reuse the tokens it receives against docs-api.
- **Client credentials for the scheduled job, not a stored admin token.** The job is the *system*, not a person. A stored admin token would misattribute every snapshot to that admin, grant far more privilege than `audit:write`, keep a powerful long-lived secret around, and break when the admin leaves.
- **Audit calls happen after the transaction commits.** A network call inside the transaction would hold row locks and a pooled database connection for its whole duration, so a slow audit-service could exhaust docs-api's connection pool.
- **Auditing fails open, loudly.** If audit-service is down, the edit still succeeds and docs-api logs the failure. A system that can't lose an audit record would use a **transactional outbox**: write the event to docs-api's own database in the same transaction, and deliver it asynchronously with retries.
- **Unknown fields are rejected, not ignored.** Silently ignoring `actorUserId` hides both forgery attempts and developer mistakes. A 400 surfaces both immediately.
- **Per-user token caching for exchanged tokens.** A single shared cache entry would make every user's edits carry whichever user's token was exchanged first: an audit trail that looks correct and blames the wrong person.
- **The realm is code.** The Keycloak realm is exported to JSON with fixed user IDs and client secrets, so the setup is reproducible and reviewable in a diff. Settings are discovered in the admin console but edited into the JSON by hand: the console's partial export masks client secrets, so re-importing it would break every confidential client.
- **CORS on docs-api is kept as a record of Phase 2.** Since the BFF, no browser calls docs-api directly, so the configuration is no longer needed. <!-- TODO: confirm keep vs. remove -->

### API keys (docs-api `/internal/**`)

- **An alternative mechanism for a different kind of caller, not an extra layer.** API keys serve machine callers that aren't registered in Keycloak, like a monitoring tool or a partner integration. Inside the system, client credentials is the better choice: short-lived tokens, scopes, central revocation. That's what docs-api itself uses toward audit-service.
- **Written by hand, not configured.** A token with enforced states (only the factory can produce an authenticated token, and it never holds the raw key), a provider, a filter and a dedicated `SecurityFilterChain`. It's the same pipeline `oauth2ResourceServer()` builds for JWTs, assembled manually.
- **Two chains, never mixed.** The API-key chain matches `/internal/**` and is ordered first; the JWT chain catches everything else. A request is authenticated one way only.
- **Keys look like `dk_<keyId>_<secret>`.** The public `keyId` makes lookup a cheap indexed query and is safe to log. Only the secret is hashed.
- **SHA-256, not BCrypt.** Keys are 256 random bits, so brute force is infeasible even against a fast hash, and BCrypt's per-record salts would make lookup by hash impossible. Comparison uses `MessageDigest.isEqual`.
- **The secret is verified before revocation and expiry are checked,** so someone holding only a `keyId` learns nothing about the key's status.
- **One undifferentiated 401 for every failure.** The specific reason (revoked, expired, wrong secret) goes to the server log with the `keyId`, never the secret. The exception messages are generic too, since exception messages travel to places the code doesn't control.
- **Revocation is instant,** because the key is checked against the database on every request. That's the trade against JWTs, which stay valid until they expire.

### Rate limiting (bff)

- **Two tiers.** An IP-keyed filter runs before Spring Security, so it sees unauthenticated traffic, including login starts, each of which creates a server-side session. A `sub`-keyed interceptor runs after security, so it only charges authenticated requests that are headed for a real handler.
- **Keyed on `sub`, not the session ID.** Anyone can drop their cookie and start a fresh session, and with it a fresh bucket. The user's identity can't be reset that way.
- **Token bucket with greedy refill.** Fixed windows allow 2N requests across a window boundary. Interval refill would reintroduce that cliff inside a token bucket.
- **Weighted cost instead of separate buckets.** Reads cost 1, writes cost more, in one bucket per user. A rejected request costs nothing.
- **Redis, with expiring keys.** Shared, atomic counts across bff instances. Without expiration, every IP that ever sent a request would leave a key behind forever, and the limiter would become a memory-exhaustion vector itself.
- **Fails closed at startup, fails open at runtime.** Redis is a startup dependency, with a compose healthcheck for ordering. Once running, a Redis outage disables limiting instead of taking the site down: controls that limit *how much* fail open, while controls that decide *who you are* fail closed. `REJECT_COMMANDS` makes failures instant while Lettuce knows Redis is down, and a 200ms command timeout covers a Redis that hangs.
- **All numbers live in configuration,** so tests can shrink them.

### Keycloak hardening

- **Brute-force mode: permanent lockout after three temporary lockouts of 25 failures each.** This caps the total number of guesses per account. The accepted cost is that anyone who knows a username can deliberately lock that account; an admin can unlock it. Temporary-only lockout is the usual choice when availability matters more or there's no one to unlock accounts. <!-- TODO: confirm this matches your reasoning -->
- **A locked account gets the same response as a wrong password,** so the response doesn't reveal the lockout.
- **User events are on, admin events are off.** Failed logins are logged. A burst against one user is brute force; a burst across many users is spraying. Events carry usernames and IPs, so retention is a privacy decision.
- **Direct access grants (the password grant) only on `dev-test-client`,** which tests use to get tokens. Never on `bff`; OAuth 2.1 drops the grant entirely.

### CI and supply chain

- **One workflow, a matrix over the three services, `fail-fast: false`,** so one run shows every broken service.
- **No path filters.** A change to `keycloak/realm-export.json` alone must still run docs-api's suites, which depend on it.
- **Least-privilege token:** `permissions: contents: read`, and `persist-credentials: false`, so the token isn't left on disk for every later step and build plugin.
- **Actions pinned to commit SHAs,** because tags are mutable pointers that a compromised upstream can repoint (as happened to `tj-actions/changed-files` in March 2025). Dependabot proposes updates as PRs, which go through the same checks.
- **`pull_request`, never `pull_request_target`,** so PR code never runs with the base repository's permissions.
- **Branch protection makes it a control:** all three checks required, branches up to date, no bypass list, no force pushes.

## Bugs that taught the most

- **Defining a custom `JwtDecoder` silently dropped the audience check.** Spring Boot's auto-configured decoder backs off, along with the properties it read. The wrong-audience test caught it.
- **Realm drift.** The running Keycloak and `realm-export.json` disagreed more than once (default roles adding an unexpected `account` audience, for example). Fixed in the UI, then re-exported.
- **The token issuer depended on the hostname** Keycloak was reached by (`localhost` from the browser, `keycloak` inside Docker), which breaks token relay. Fixed by configuring Keycloak's hostname rather than working around it in each service.
- **The bff's relay never forwarded request bodies.** It surfaced as `Required request body is missing` on docs-api when sharing a document. The browser had sent the body; the relay dropped it.
- **A copied realm user broke every Keycloak test at once.** Seeding `lockout-target` by copying alice's entry kept her email; Keycloak requires unique emails, so the realm import failed. The shared container starts in a static initializer, so one failure surfaced as a wall of `NoClassDefFoundError`s in unrelated classes. The real error is always the *first* one.
- **Fail-open that wasn't fast.** With Redis stopped, requests succeeded but each one waited out the command timeout, because Lettuce queues commands while it reconnects. `REJECT_COMMANDS` made failures instant. Left alone, a slow fail-open would have tied up request threads under load.
- **A rate limiter that silently had no limits.** A YAML prefix that didn't match the properties record left both tiers `null`, and records bind missing nested values without complaint. It only surfaced as an NPE when the bucket configuration was built.

## Possible next steps

- TOTP or passkeys through Keycloak's built-in flows (the real fix for password spraying)
- An `azp` allowlist on docs-api, and Keycloak admin events
- Opaque tokens with introspection instead of JWTs
- mTLS between services
- A transactional outbox for audit events