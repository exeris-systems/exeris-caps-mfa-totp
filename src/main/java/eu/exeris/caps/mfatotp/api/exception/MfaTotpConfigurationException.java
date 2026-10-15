package eu.exeris.caps.mfatotp.api.exception;

/**
 * Required configuration is missing or malformed. The message names the configuration key and never
 * carries a configured value.
 */
public class MfaTotpConfigurationException extends MfaException {

    private final String key;

    public MfaTotpConfigurationException(String key, String message) {
        super(key + ": " + message);
        this.key = key;
    }

    public MfaTotpConfigurationException(String key, String message, Throwable cause) {
        super(key + ": " + message, cause);
        this.key = key;
    }

    public String key() {
        return key;
    }
}
