package com.korbei.rs.jwt.configuration;

import com.auth0.jwt.algorithms.Algorithm;

import java.util.Optional;

/**
 * JWT configuration interface.
 */
public interface JwtConfigurationProvider {
    /**
     * The Algorithm defines how a token is signed and verified. It can be instantiated with the raw value of the secret
     * in the case of HMAC algorithms, or the key pairs or KeyProvider in the case of RSA and ECDSA algorithms.
     * Once created, the instance is reusable for token signing and verification operations.
     * @return the signing algorithm
     *
     * @see <a href="https://github.com/auth0/java-jwt">https://github.com/auth0/java-jwt</a>
     */
    Algorithm getAlgorithm();

    /**
     * Identifies the JWT token issuer.
     * @return the issuer
     */
    String getIssuer();

    /**
     * Identifies the recipients that the JWT token is intended for.
     * @return the audience
     */
    String[] getAudience();

    /**
     * Define the default window in seconds in which the Not Before, Issued At and Expires At Claims will still be valid.
     * Setting a specific leeway value on a given Claim will override this value for that Claim
     * @return leeway the window in seconds in which the Not Before, Issued At and Expires At Claims will still be valid
     *
     * @see com.auth0.jwt.interfaces.Verification#acceptLeeway(long)
     */
    default Optional<Long> getAcceptLeeway() {
        return Optional.empty();
    }
}
