package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.TotpFactorRegistry;
import eu.exeris.caps.mfatotp.api.TotpVerifier;
import eu.exeris.caps.mfatotp.api.exception.FactorAlreadyEnrolledException;
import eu.exeris.caps.mfatotp.api.exception.FactorNotFoundException;
import eu.exeris.caps.mfatotp.api.exception.InvalidTotpCodeException;
import eu.exeris.caps.mfatotp.api.model.TotpEnrollmentSession;
import eu.exeris.caps.mfatotp.api.model.TotpFactorStatus;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.crypto.Rfc6238Totp;
import eu.exeris.caps.mfatotp.internal.repository.FactorRecord;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class DefaultTotpFactorRegistry implements TotpFactorRegistry {

    private final MfaRepository repository;
    private final TotpVerifier verifier;
    private final MfaAuditBridge auditBridge;
    private final String issuer;

    public DefaultTotpFactorRegistry(
            MfaRepository repository,
            TotpVerifier verifier,
            MfaAuditBridge auditBridge,
            String issuer
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.verifier = Objects.requireNonNull(verifier, "verifier must not be null");
        this.auditBridge = auditBridge;
        this.issuer = (issuer != null && !issuer.isBlank()) ? issuer : "Exeris";
    }

    @Override
    public TotpEnrollmentSession beginEnrollment(UUID subjectId, String accountLabel) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(accountLabel, "accountLabel must not be null");

        Optional<FactorRecord> existing = repository.findFactorBySubjectId(subjectId);
        if (existing.isPresent() && existing.get().enabled()) {
            throw new FactorAlreadyEnrolledException(subjectId);
        }

        String pendingSecret = Rfc6238Totp.generateSecret();
        Instant now = Instant.now();

        FactorRecord record = existing.map(rec -> new FactorRecord(
                rec.id(), subjectId, rec.secret() != null ? rec.secret() : "", pendingSecret,
                false, null, null, rec.createdAt(), now
        )).orElseGet(() -> new FactorRecord(
                UUID.randomUUID(), subjectId, "", pendingSecret,
                false, null, null, now, now
        ));

        repository.saveFactor(record);

        String provisioningUri = buildProvisioningUri(pendingSecret, accountLabel);
        return new TotpEnrollmentSession(subjectId, pendingSecret, provisioningUri);
    }

    @Override
    public TotpFactorStatus confirmEnrollment(UUID subjectId, String code) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(code, "code must not be null");

        FactorRecord record = repository.findFactorBySubjectId(subjectId)
                .orElseThrow(() -> new FactorNotFoundException(subjectId));

        if (record.pendingSecret() == null || record.pendingSecret().isBlank()) {
            throw new InvalidTotpCodeException();
        }

        boolean valid = verifier.verifyRaw(record.pendingSecret(), code);
        if (!valid) {
            throw new InvalidTotpCodeException();
        }

        Instant now = Instant.now();
        FactorRecord activated = new FactorRecord(
                record.id(), subjectId, record.pendingSecret(), null,
                true, now, now, record.createdAt(), now
        );

        repository.saveFactor(activated);

        if (auditBridge != null) {
            auditBridge.logFactorEnrolled(subjectId);
        }

        return new TotpFactorStatus(subjectId, true, now, now);
    }

    @Override
    public void disableFactor(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");

        FactorRecord record = repository.findFactorBySubjectId(subjectId)
                .orElseThrow(() -> new FactorNotFoundException(subjectId));

        if (!record.enabled()) {
            throw new FactorNotFoundException(subjectId);
        }

        repository.deleteFactor(subjectId);

        if (auditBridge != null) {
            auditBridge.logFactorDisabled(subjectId);
        }
    }

    @Override
    public TotpFactorStatus getStatus(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.findFactorBySubjectId(subjectId)
                .map(r -> new TotpFactorStatus(subjectId, r.enabled(), r.enrolledAt(), r.lastVerifiedAt()))
                .orElseGet(() -> TotpFactorStatus.notEnrolled(subjectId));
    }

    private String buildProvisioningUri(String base32Secret, String accountLabel) {
        String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8);
        String encodedAccount = URLEncoder.encode(accountLabel, StandardCharsets.UTF_8);
        return "otpauth://totp/"
                + encodedIssuer + ":" + encodedAccount
                + "?secret=" + base32Secret
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1&digits=6&period=30";
    }
}
