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
 */
public interface MfaChallenge {

    /**
     * Issues a short-lived challenge token for a subject upon successful password verification.
     *
     * @param subjectId the subject UUID
     * @param ttl       time-to-live for the challenge (e.g. 5 minutes)
     * @return issued challenge containing the opaque token string
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
