package eu.exeris.caps.mfatotp.api.model;

import java.util.Objects;
import java.util.UUID;

/**
 * An in-progress enrollment session containing the secret and provisioning URI.
 */
public record TotpEnrollmentSession(
        UUID subjectId,
        String secret,
        String provisioningUri
) {
    public TotpEnrollmentSession {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(secret, "secret must not be null");
        Objects.requireNonNull(provisioningUri, "provisioningUri must not be null");
    }
}
