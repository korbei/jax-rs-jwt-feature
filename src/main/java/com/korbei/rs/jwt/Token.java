package com.korbei.rs.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.korbei.rs.jwt.configuration.JwtConfigurationProvider;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.spi.CDI;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class Token {
    private static Algorithm algorithm;
    private static String issuer;
    private static JWTVerifier verifier;

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
        verifier = JWT.require(algorithm)
                .withIssuer(issuer)
                .acceptLeeway(leeway.orElse(0L))
                .build();

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
     * Wrapper class of JWTCreator.Builder
     */
    public static class TokenBuilder {
        private JWTCreator.Builder builder;

        private TokenBuilder() {
            builder = JWT.create()
                    .withIssuer(issuer)
                    .withIssuedAt(new Date());
        }

        public TokenBuilder withHeader(Map<String, Object> headerClaims) {
            builder.withHeader(headerClaims);
            return this;
        }

        public TokenBuilder withKeyId(String keyId) {
            builder.withKeyId(keyId);
            return this;
        }

        public TokenBuilder withIssuer(String issuer) {
            builder.withIssuer(issuer);
            return this;
        }

        public TokenBuilder withSubject(String subject) {
            builder.withSubject(subject);
            return this;
        }

        public TokenBuilder withAudience(String... audience) {
            builder.withAudience(audience);
            return this;
        }

        public TokenBuilder withExpiresAt(Date expiresAt) {
            builder.withExpiresAt(expiresAt);
            return this;
        }

        public TokenBuilder withNotBefore(Date notBefore) {
            builder.withNotBefore(notBefore);
            return this;
        }

        public TokenBuilder withIssuedAt(Date issuedAt) {
            builder.withIssuedAt(issuedAt);
            return this;
        }

        public TokenBuilder withJWTId(String jwtId) {
            builder.withJWTId(jwtId);
            return this;
        }

        public TokenBuilder withClaim(String name, Boolean value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        public TokenBuilder withClaim(String name, Integer value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        public TokenBuilder withClaim(String name, Long value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        public TokenBuilder withClaim(String name, Double value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        public TokenBuilder withClaim(String name, String value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        public TokenBuilder withClaim(String name, Date value) throws IllegalArgumentException {
            builder.withClaim(name, value);
            return this;
        }

        public TokenBuilder withRoles(String... roles) throws IllegalArgumentException {
            Objects.requireNonNull(roles, "Roles can't be null!");
            builder.withArrayClaim(Const.CLAIM_ROLES, roles);
            return this;
        }

        public TokenBuilder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            builder.withArrayClaim(name, items);
            return this;
        }

        public TokenBuilder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            builder.withArrayClaim(name, items);
            return this;
        }

        public TokenBuilder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            builder.withArrayClaim(name, items);
            return this;
        }

        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            return builder.sign(algorithm);
        }

        public String sign() throws IllegalArgumentException, JWTCreationException {
            return builder.sign(algorithm);
        }
    }
}
