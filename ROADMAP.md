---
title: "Roadmap of the MFA TOTP capability"
type: roadmap
visibility: public
owning-repo: exeris-caps-mfa-totp
status: active
last-verified: 2026-10-15
---

# Roadmap of the MFA TOTP capability

This file records what the proof of concept does not cover. It is read together with the code, and the pull request that closes a gap updates the item it closes. An item under "Before 0.1.0" has a tracking issue in the `0.1.0` milestone, so the milestone shows what blocks the first release; an item under "Later" has none until it is scheduled.

Milestones are versions, not dates.

The capability provides `TotpFactorRegistry`, `TotpVerifier`, `RecoveryCodes` and `MfaChallenge`, each at version `0.1.0`, and is a proof of concept with no published artefact. [`README.md`](README.md) describes what it does; the review rules in [`docs/repo-review-rules.md`](docs/repo-review-rules.md) state the invariants a change must keep.

## Before 0.1.0

Each item is a property that the Identity SKU (ADR-099) relies on and that the code does not hold, or a statement the README makes that the code does not meet.

### The challenge cannot tell that the password check succeeded

[#12](https://github.com/exeris-systems/exeris-caps-mfa-totp/issues/12). `MfaChallenge.issue` mints a challenge for any subject it is asked about, and nothing in the call carries evidence of a successful password check. Rule S11 requires that a challenge cannot be issued for a subject whose password check has not succeeded, so today the property rests on the calling code, and the README records it as a limit. A caller that skips the password step reaches the second factor with a valid challenge. The change reshapes the signature of `issue` (a receipt from a credential store, or a service contract that `issue` calls), which is cheaper before release than after. Code: `src/main/java/eu/exeris/caps/mfatotp/api/MfaChallenge.java`, `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultMfaChallenge.java`.

## Later

### Attempt limiting is the caller's duty

`TotpVerifier.verify` and `RecoveryCodes.verifyAndConsume` keep no failure counter and are not bound to a challenge. The limit lives in `MfaChallenge` (`maxAttempts`, default 5) and applies only when the caller validates the challenge, calls `recordFailure` on every failure and calls `consume` on success. A caller that omits the sequence can try all of the six-digit codes of a factor. `recordFailure` also increments a challenge that is consumed or expired. Attempt limiting belongs with the rate-limiting capability and the composition of the SKU, which decide the budget per subject, address and window; the counter of this capability is one input to that policy. Waits on: the rate-limiting capability and the Identity SKU's composition, then a verification entry point that charges each attempt to a challenge in one unit, which can share a contract change with the receipt above. Code: `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultTotpVerifier.java`, `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultRecoveryCodes.java`, `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultMfaChallenge.java`.

### Take `TransactionalExecutor` from the kernel instead of the constructor

`MfaTotpModule` declares `@Requires(service = TransactionalExecutor.class, optional = true)` and receives the executor through its wired constructors, so the manifest under-states what the capability needs to start, and `initialize()` does nothing with the kernel. The requirement stays optional because the tooling reports a `@Requires` on a kernel SPI type as unsatisfied (EXT-PLUG-2201), tracked as [exeris-tooling#409](https://github.com/exeris-systems/exeris-tooling/issues/409). The kernel `0.13` line binds `KernelProviders.TRANSACTIONAL_EXECUTOR` when persistence is configured (`CommunityPersistenceSubsystem` on `development/0.13.0`). Waits on: exeris-tooling#409, then a change that reads the provider in `initialize()` and marks the requirement non-optional. Code: `src/main/java/eu/exeris/caps/mfatotp/MfaTotpModule.java`.

### Step-up for factor changes

`TotpFactorRegistry.disableFactor`, `beginEnrollment` and `RecoveryCodes.regenerate` act on a subject without any proof that the caller holds a verified session or a second factor, and `confirmEnrollment` has no attempt limit. Whoever can call the service can remove or replace a subject's second factor. The capability states no rule for who may call these methods. Waits on: a decision, in the Identity SKU's design, on where the step-up check lives (session, challenge or this capability), recorded as a rule before any signature changes. Code: `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultTotpFactorRegistry.java`, `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultRecoveryCodes.java`.

### Audit events are best effort

`MfaAuditBridge` swallows every exception from the sink, and the sink is an optional requirement, so a security event (a failed verification, a locked challenge, a disabled factor) can be lost without the operation failing, and a composition without `AuditLogSink` records nothing. This is deliberate in the code today ("audit failures must not fail security transactions"). Whether an Identity composition needs durable audit, and whether it then needs to fail the operation or record the loss elsewhere, is a design question for ADR-099. Code: `src/main/java/eu/exeris/caps/mfatotp/internal/audit/MfaAuditBridge.java`.

### Challenge hygiene

Nothing deletes consumed or expired rows of `mfa_challenges`, so the table grows with every login, and `issue` does not invalidate a subject's earlier open challenges, so a subject can hold several live tokens each with its own attempt budget. The first costs storage and index size, the second multiplies the guesses available to an attacker who can trigger challenges. Waits on: the attempt-limiting item above, because the budget may move from the challenge to the subject. Code: `src/main/java/eu/exeris/caps/mfatotp/internal/repository/PostgresMfaRepository.java`, `src/main/java/eu/exeris/caps/mfatotp/internal/DefaultMfaChallenge.java`.

### Pepper keyring

One pepper keys the hashes of recovery codes and challenge tokens, so rotating it invalidates every stored recovery code and every open challenge. The TOTP seeds already have a keyring with an active key and `resealWithActiveKey()`; the hashes cannot be re-sealed because the plaintext is not stored. A rotation that keeps old hashes valid needs a keyed lookup by key id. Waits on: the shape of the hash column (a key id beside the hash), which is a schema change to `V1__create_mfa_totp.sql`, and a decision on whether a recovery-code rotation may instead force users to regenerate. Code: `src/main/java/eu/exeris/caps/mfatotp/internal/crypto/TokenHasher.java`, `src/main/java/eu/exeris/caps/mfatotp/MfaTotpModule.java`.

### The PostgreSQL integration test does not run in CI

`PostgresMfaRepositoryLiveIT` is skipped unless `EXERIS_TEST_PG_URL`, `EXERIS_TEST_PG_USER` and `EXERIS_TEST_PG_PASSWORD` are set, and the build workflow has no PostgreSQL service. The concurrency claim of the replay check (concurrent presentations of one code admit one) and the sealed-envelope binding are therefore tested against a real database only on a local run. Waits on: a CI job with a database service, or a decision that the organisation's workflows provide one. Code: `src/test/java/eu/exeris/caps/mfatotp/internal/repository/PostgresMfaRepositoryLiveIT.java`, `.github/workflows/build.yml`.

### Applying the migration

The capability ships `V1__create_mfa_totp.sql` and lists it in `MfaTotpModule.MIGRATIONS`, and applies nothing itself; the composing SKU applies it before the first call. There is no check at start-up that the schema exists, so a missing migration fails at the first query rather than at boot. Waits on: the Identity SKU's migration runner, and a decision on whether a capability verifies its schema in `initialize()`. Code: `src/main/java/eu/exeris/caps/mfatotp/MfaTotpModule.java`.

### Seed exposure in the process

The seed is plaintext in the process while a code is checked, and in the enrolment response that shows it to the user once. Sealing protects it at rest only. Narrowing the exposure (zeroing the decoded key material, a response type that is not retained) is hardening with no change to the contract. Code: `src/main/java/eu/exeris/caps/mfatotp/internal/crypto/Rfc6238Totp.java`, `src/main/java/eu/exeris/caps/mfatotp/api/model/TotpEnrollmentSession.java`.

### Review rule S5 names only the kernel SPI

`docs/repo-review-rules.md` S5 lists the kernel SPI as the runtime classpath, while S1 now treats the public packages of `exeris-kernel-core` as nameable by a capability, so a compile-scope Core dependency is legal under S1 and a `[CONTRACT]` finding under S5. The wording of S5 should follow S1. Code: `docs/repo-review-rules.md`.
