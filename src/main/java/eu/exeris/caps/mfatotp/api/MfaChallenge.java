package eu.exeris.caps.mfatotp.api;

import eu.exeris.caps.mfatotp.api.exception.ChallengeExpiredException;
import eu.exeris.caps.mfatotp.api.exception.ChallengeLockedException;
import eu.exeris.caps.mfatotp.api.exception.InvalidChallengeException;
import eu.exeris.caps.mfatotp.api.model.ChallengeStatus;
import eu.exeris.caps.mfatotp.api.model.IssuedChallenge;

import java.time.Duration;
import java.util.UUID;

/**
 * Service for issuing and consuming short-lived MFA login challenge tokens.
 *
 * <p>The challenge is what limits attempts: it locks after a fixed number of {@link #recordFailure} calls.
 * The service cannot observe a verification, so the caller records each failure.
 */
public interface MfaChallenge {

    /**
     * Issues a short-lived challenge token for a subject. Issuing is the caller's step after a successful
     * password check: this service cannot establish that check, and mints a challenge for any subject it is
     * asked about, so only the code that has verified the password may call it.
     *
     * @param subjectId the subject UUID
     * @param ttl       time-to-live; {@code null} for the configured default, longer than the configured
     *                  maximum is clamped to it
     * @return issued challenge containing the opaque token string
     * @throws IllegalArgumentException if {@code ttl} is zero or negative
     */
    IssuedChallenge issue(UUID subjectId, Duration ttl);

    /**
     * Validates challenge state and checks if it can be consumed.
     *
     * @param rawToken the raw challenge token string
     * @return status of the challenge
     * @throws InvalidChallengeException if challenge is not found or already consumed
     * @throws ChallengeExpiredException  if challenge has expired
     * @throws ChallengeLockedException   if challenge is locked due to too many failed attempts
     */
    ChallengeStatus validate(String rawToken);

    /**
     * Records a failed factor verification attempt against this challenge, incrementing counter.
     *
     * @param rawToken the raw challenge token string
     */
    void recordFailure(String rawToken);

    /**
     * Consumes the challenge upon successful factor verification (replay protection).
     *
     * @param rawToken the raw challenge token string
     * @return the subject UUID associated with the challenge
     */
    UUID consume(String rawToken);
}
