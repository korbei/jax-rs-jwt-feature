package com.korbei.rs.jwt.configuration;

import com.auth0.jwt.algorithms.Algorithm;

import javax.annotation.PostConstruct;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Default implementation of the JwtConfigurationProvider interface
 */
public class DefaultJwtConfigurationProvider implements JwtConfigurationProvider {
    private Algorithm alg;

    @PostConstruct
    private void init() {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(1024, SecureRandom.getInstance("SHA1PRNG"));

            final KeyPair keyPair = keyGen.genKeyPair();
            final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            alg = Algorithm.RSA256(publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Algorithm getAlgorithm() {
        return alg;
    }

    @Override
    public String[] getAudience() {
        return new String[]{"easy-jwt"};
    }

    @Override
    public String getIssuer() {
        return "easy-jwt";
    }
}

