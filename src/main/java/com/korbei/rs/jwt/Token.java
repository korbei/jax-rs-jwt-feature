package com.korbei.rs.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.korbei.rs.jwt.configuration.JwtConfigurationProvider;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.CDI;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class Token {
    private static Algorithm algorithm;
    private static JWTVerifier verifier;
    private static String issuer;
    private static Optional<String[]> audience;

    static {
        final Instance<JwtConfigurationProvider> sInstance = CDI.current().select(JwtConfigurationProvider.class);
        if (sInstance.isUnsatisfied()) {
            //WTF how do we get here there is a default implementation
            throw new RuntimeException("There is no available JwtConfigurationProvider instance!");
        }

        if (sInstance.isAmbiguous()) {
            throw new RuntimeException("There is multiple JwtConfigurationProvider instance!");
        }

        final JwtConfigurationProvider settingsProvider = sInstance.get();
        final Optional<Long> leeway = settingsProvider.getAcceptLeeway();
        algorithm = settingsProvider.getAlgorithm();
        issuer = settingsProvider.getIssuer();
        audience = settingsProvider.getAudience();

        Verification verification = JWT.require(algorithm)
                .withIssuer(issuer)
                .acceptLeeway(leeway.orElse(0L));

        if(audience.isPresent()) {
            verification = verification.withAudience(audience.get());
        }

        verifier = verification.build();

        sInstance.destroy(settingsProvider);
    }

    /**
     * Perform the verification against the given Token, using any previous configured options.
     *
     * @param token to verify.
     * @throws JWTVerificationException if the token invalid
     * @see com.auth0.jwt.JWTVerifier#verify(String)
     */
    public static DecodedJWT verify(String token) throws JWTVerificationException {
        return verifier.verify(token);
    }

    /**
     * Decode a given Json Web Token.
     * <p>
     * Note that this method <b>doesn't verify the token's signature!</b> Use it only if you trust the token or you
     * already verified it.
     *
     * @param token with jwt format as string.
     * @return a decoded JWT.
     * @throws JWTDecodeException if any part of the token contained an invalid jwt or JSON format of each of the jwt
     *                            parts.
     * @see com.auth0.jwt.JWT#decode(String)
     */
    public static DecodedJWT decode(String token) throws JWTDecodeException {
        return JWT.decode(token);
    }

    /**
     * @return a token builder.
     */
    public static TokenBuilder create() {
        return new TokenBuilder();
    }

    /**
     * Wrapper class for JWTCreator.Builder
     */
    public static class TokenBuilder {
        private JWTCreator.Builder builder;

        private TokenBuilder() {
            builder = JWT.create()
                    .withIssuer(issuer)
                    .withAudience(audience.orElse(null))
                    .withIssuedAt(new Date());
        }

        /**
         * Add specific Claims to set as the Header.
         *
         * @param headerClaims the values to use as Claims in the token's Header.
         * @return this same Builder instance.
         */
        public TokenBuilder withHeader(Map<String, Object> headerClaims) {
            builder.withHeader(headerClaims);
            return this;
        }

        /**
         * Add a specific Key Id ("kid") claim to the Header.
         * If the {@link Algorithm} used to sign this token was instantiated with a KeyProvider, the 'kid' value will be taken from that provider and this one will be ignored.
         *
         * @param keyId the Key Id value.
         * @return this same Builder instance.
         */
        public TokenBuilder withKeyId(String keyId) {
            builder.withKeyId(keyId);
            return this;
        }

        /**
         * Add a specific Issuer ("iss") claim to the Payload.
         *
         * @param issuer the Issuer value.
         * @return this same Builder instance.
         */
        public TokenBuilder withIssuer(String issuer) {
            builder.withIssuer(issuer);
            return this;
        }

        /**
         * Add a specific Subject ("sub") claim to the Payload.
         *
         * @param subject the Subject value.
         * @return this same Builder instance.
         */
        public TokenBuilder withSubject(String subject) {
            builder.withSubject(subject);
            return this;
        }

        /**
         * Add a specific Audience ("aud") claim to the Payload.
         *
         * @param audience the Audience value.
         * @return this same Builder instance.
         */
        public TokenBuilder withAudience(String... audience) {
            builder.withAudience(audience);
            return this;
        }

        /**
         * Add a specific Expires At ("exp") claim to the Payload.
         *
         * @param expiresAt the Expires At value.
         * @return this same Builder instance.
         */
        public TokenBuilder withExpiresAt(Date expiresAt) {
            builder.withExpiresAt(expiresAt);
            return this;
        }

        /**
         * Add a specific Not Before ("nbf") claim to the Payload.
         *
         * @param notBefore the Not Before value.
         * @return this same Builder instance.
         */
        public TokenBuilder withNotBefore(Date notBefore) {
            builder.withNotBefore(notBefore);
            return this;
        }

        /**
         * Add a specific Issued At ("iat") claim to the Payload.
         *
         * @param issuedAt the Issued At value.
         * @return this same Builder instance.
         */
        public TokenBuilder withIssuedAt(Date issuedAt) {
            builder.withIssuedAt(issuedAt);
            return this;
        }

        /**
         * Add a specific JWT Id ("jti") claim to the Payload.
         *
         * @param jwtId the Token Id value.
         * @return this same Builder instance.
         */
        public TokenBuilder withJWTId(String jwtId) {
            builder.withJWTId(jwtId);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withClaim(String name, Boolean value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withClaim(String name, Integer value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withClaim(String name, Long value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withClaim(String name, Double value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withClaim(String name, String value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        /**
         * Add a custom Claim value.
         *
         * @param name  the Claim's name.
         * @param value the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withClaim(String name, Date value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        /**
         * Add a specific roles ("roles") claim to the Payload.
         *
         * @param roles the roles value.
         * @return this same Builder instance.
         */
        public TokenBuilder withRoles(String... roles) throws IllegalArgumentException {
            Objects.requireNonNull(roles, "Roles can't be null!");
            builder.withArrayClaim(Const.CLAIM_ROLES, roles);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            builder.withArrayClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            builder.withArrayClaim(name, items);
            return this;
        }

        /**
         * Add a custom Array Claim with the given items.
         *
         * @param name  the Claim's name.
         * @param items the Claim's value.
         * @return this same Builder instance.
         * @throws IllegalArgumentException if the name is null.
         */
        public TokenBuilder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            builder.withArrayClaim(name, items);
            return this;
        }

        /**
         * Creates a new JWT and signs is with the given algorithm
         *
         * @param algorithm used to sign the JWT
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            return builder.sign(algorithm);
        }

        /**
         * Creates a new JWT and signs is with the algorithm provided by <code>{@link JwtConfigurationProvider}</code>
         *
         * @return a new JWT token
         * @throws IllegalArgumentException if the provided algorithm is null.
         * @throws JWTCreationException     if the claims could not be converted to a valid JSON or there was a problem with the signing key.
         */
        public String sign() throws IllegalArgumentException, JWTCreationException {
            return builder.sign(algorithm);
        }
    }
}
