package eu.exeris.caps.mfatotp.api.exception;

/**
 * A stored TOTP secret cannot be opened: it is not a sealed envelope, names a key the keyring does not
 * hold, or fails authentication. The secret is refused; nothing falls back to plaintext.
 */
public class TotpSecretCustodyException extends MfaException {

    /** Why the stored value was refused. */
    public enum Reason {
        NOT_SEALED,
        UNKNOWN_KEK,
        AUTHENTICATION_FAILED
    }

    private final Reason reason;

    public TotpSecretCustodyException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public TotpSecretCustodyException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
