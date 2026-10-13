# exeris-caps-mfa-totp

Time-based one-time passwords as an Exeris capability. It provides `TotpFactorRegistry` (begin enrolment with a secret and provisioning URI, confirm, disable), `TotpVerifier` (RFC 6238 verification), `RecoveryCodes` (batches of single-use codes, stored hashed) and `MfaChallenge` (the short-lived step between a password check and the second factor).

Status: proof of concept, built against `exeris-kernel` 0.13.0-SNAPSHOT. The API is not stable and no artefact has been published.

## Where it sits

- **Layer:** Layer 5 — Domain primitive (identity), in the Tier 2 capability map of [`high-level-architecture.md`](https://github.com/exeris-systems/exeris-docs/blob/main/high-level-architecture.md) §3.2.
- **Depends on:** `exeris-kernel-spi`, `exeris-sdk-composition-lifecycle` and `exeris-caps-audit-trail`.
- **Provides** (`@Provides`, all version 0.1.0): `TotpFactorRegistry`, `TotpVerifier`, `RecoveryCodes`, `MfaChallenge`.
- **Requires** (`@Requires`, each declared `optional = true`): `eu.exeris.kernel.spi.persistence.TransactionalExecutor`, `eu.exeris.caps.audittrail.api.AuditLogSink`.
- **Wall (ADR-055):** `eu.exeris.caps.mfatotp.api` is the cross-cap surface; `eu.exeris.caps.mfatotp.internal` is private, and a sibling cap reaching into it fails the build. No Spring, servlet, Netty or reactive type may appear (ADR-006).

Behaviour worth knowing before composing it:

- Storage is PostgreSQL through a kernel `TransactionalExecutor`; there is no in-memory store. The composition conductor's no-arg instance only runs the lifecycle hooks and its service accessors throw. The composing SKU builds the wired instance with `new MfaTotpModule(tx, auditLogSink, issuer)` and applies `MfaTotpModule.MIGRATIONS` (`src/main/resources/db/migration/exeris-caps-mfa-totp/V1__create_mfa_totp.sql`) first; the capability applies nothing itself.
- A TOTP time step is accepted once per factor: `TotpVerifier.verify` refuses a code whose step is not greater than the last one accepted, with a single conditional `UPDATE`, so concurrent presentations of one code admit one.
- Attempt limiting is the caller's duty. `TotpVerifier` and `RecoveryCodes` keep no failure counter; the caller validates an `MfaChallenge` first, calls `recordFailure` on every failure and `consume` on success. `MfaChallenge.issue` must only follow a successful password check, which this capability cannot establish.

## Configuration

The wired constructors read their configuration from the environment (or a `Map` passed to the constructor) when they are called. A missing or malformed required value throws `MfaTotpConfigurationException`, which names the key and never carries a value, so the deployment fails to boot.

| Key | Required | Default | Meaning |
|---|---|---|---|
| `EXERIS_MFA_TOTP_PEPPER` | yes (or `_FILE`) | – | Base64 of at least 32 random bytes; keys the HMAC-SHA256 of recovery codes and challenge tokens |
| `EXERIS_MFA_TOTP_PEPPER_FILE` | yes (or inline) | – | path to a file holding the same value, such as a mounted secret |
| `EXERIS_MFA_TOTP_KEKS` | yes (or `_FILE`) | – | key-encryption keyring, `<id>:<base64>[,<id>:<base64>…]` |
| `EXERIS_MFA_TOTP_KEKS_FILE` | yes (or inline) | – | path to a file holding the same keyring |
| `EXERIS_MFA_TOTP_CHALLENGE_TTL` | no | `PT5M` | lifetime of a challenge issued without one |
| `EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL` | no | `PT10M` | upper bound on any challenge lifetime; a longer request is clamped |

Set exactly one of each inline/file pair. The pepper and each key must come from a CSPRNG, for example `openssl rand -base64 32`; a passphrase is refused, not stretched into a key, and there is no built-in value. Durations are ISO-8601.

## Security notes

- **Hashed:** recovery codes and challenge tokens are stored as HMAC-SHA256 under the pepper. A database read yields no usable code or token. Rotating the pepper invalidates every stored recovery code and open challenge.
- **Sealed:** a TOTP seed cannot be hashed, so `mfa_factors.secret` and `pending_secret` hold AES-256-GCM envelopes. An envelope names the key that sealed it and is bound to its row id, subject and column, so a value copied to another row or column fails authentication. The first keyring entry seals; the others only open. To rotate a key, prepend the new entry, call `PostgresMfaRepository.resealWithActiveKey()`, then remove the old entry. A stored value that is not an envelope, names an unknown key or fails authentication throws `TotpSecretCustodyException`; nothing falls back to plaintext.
- **Not covered:** the seed is plaintext in the process while a code is checked, and in the enrolment response that shows it to the user once.

## Build & test

Requires JDK 25 and Maven 3.9+.

```bash
mvn compile -Dexeris.codegen.skip=true   # pass 1 — the processor writes capability metadata
mvn verify                               # pass 2 — generate cap-manifest.json, validate the graph, scan the Wall
```

Both passes are needed after a `clean`: `exeris:generate` runs before `compile`, and `compile` is when the processor writes the metadata it reads. `src/main/generated/java/cap-manifest.json` is committed, so a clean `git status` after `mvn verify` shows the manifest matches the declaration.

The upstreams are not on Maven Central. `exeris-sdk` v0.12.0 and `exeris-tooling` v0.9.0 are built from source at those tags, and `exeris-kernel` 0.13.0-SNAPSHOT is resolved from GitHub Packages, which needs a token with `read:packages`; the sibling `exeris-caps-service-boundary-core` and `exeris-caps-audit-trail` are built from source first. [`.github/workflows/build.yml`](.github/workflows/build.yml) is the exact sequence, and [`.github/maven-settings.xml`](.github/maven-settings.xml) the repository configuration it uses.

## Documentation

- [`AGENTS.md`](AGENTS.md) — the repository's operating contract and invariants.
- [Capability Author Guide](https://github.com/exeris-systems/exeris-docs/blob/main/cap-author-guide.md) — how a cap declares `@CapabilityModule`, `@Provides`, `@Requires` and `@CapabilityLifecycle`.
- [Capability licence registry](https://github.com/exeris-systems/exeris-docs/blob/main/cap-license-registry.md) — the licence value of every cap.

Where they disagree, the ADRs below and the HLA outrank this README.

## Governing ADRs

- [ADR-006](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-006-spring-free-kernel-boundary.md) — Spring-free kernel boundary.
- [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md) — capability licensing taxonomy.
- [ADR-024](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-024-capability-composition-model.md) — capability composition model.
- [ADR-053](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-053-sku-composition-manifest-format.md) — composition manifest format.
- [ADR-055](https://github.com/exeris-systems/exeris-tooling/blob/main/docs/adr/ADR-055-cap-tier-wall-guard.md) — cap-tier Wall guard.
- [ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md) — signed licence manifest.
- [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md) — capability entitlement enforcement.
- [ADR-099](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-099-compose-identity-as-a-tier-3-platform-sku.md) — the Identity SKU, which lists this cap.

Registry: [`adr-index.md`](https://github.com/exeris-systems/exeris-docs/blob/main/adr-index.md).

## License

Exeris Commercial License 1.1 — see [`LICENSE`](LICENSE). `exeris-caps-mfa-totp` is a `commercial` capability under [ADR-023](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-023-capability-licensing-taxonomy.md): the source is available to read, build, test and evaluate, and production use requires a commercial licence.

The cap enforces that at boot. It registers a kernel `EntitlementRequirement` whose capability id is `exeris-caps-mfa-totp`, and in a production-class environment the kernel's contract gate refuses to start unless a signed licence manifest lists that id among its entitlements ([ADR-088](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-088-cryptographic-license-manifest-and-offline-verification.md), [ADR-089](https://github.com/exeris-systems/exeris-docs/blob/main/adr/ADR-089-capability-entitlement-enforcement-and-runtime-contract.md)).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Report a suspected vulnerability as described in [`SECURITY.md`](SECURITY.md), never in a public issue.
