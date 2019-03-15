package com.korbei.rs.jwt;


import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.jboss.weld.junit5.auto.AddPackages;
import org.jboss.weld.junit5.auto.EnableAutoWeld;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

@EnableAutoWeld
@AddPackages(Token.class)
class TokenTest {

    @Test
    void tokenTest() {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MINUTE, 1);

        final String jwtId = UUID.randomUUID().toString();

        final String[] roles = {"admin", "user"};
        final String token = Token.create()
                .withSubject("korbei")
                .withIssuer("easy-jwt")
                .withRoles(roles)
                .withExpiresAt(calendar.getTime())
                .withIssuedAt(new Date())
                .withAudience("audience")
                .withJWTId(jwtId)
                .withClaim("claim1", "stringClaim")
                .withClaim("claim2", 1)
                .withClaim("claim3", true)
                .withClaim("claim4", 2L)
                .withClaim("claim5", 3.14)
                .sign();

        Assertions.assertNotNull(token);

        Token.verify(token);

        final DecodedJWT decodedJWT = Token.decode(token);

        Assertions.assertEquals(jwtId, decodedJWT.getId());
        Assertions.assertEquals("stringClaim", decodedJWT.getClaim("claim1").as(String.class));
        Assertions.assertEquals(Integer.valueOf(1), decodedJWT.getClaim("claim2").as(Integer.class));
        Assertions.assertTrue(decodedJWT.getClaim("claim3").as(Boolean.class));
        Assertions.assertEquals(Long.valueOf(2), decodedJWT.getClaim("claim4").as(Long.class));
        Assertions.assertEquals(Double.valueOf(3.14), decodedJWT.getClaim("claim5").as(Double.class));
        Assertions.assertEquals("korbei", decodedJWT.getSubject());
        Assertions.assertEquals("easy-jwt", decodedJWT.getIssuer());
        Assertions.assertEquals("audience", decodedJWT.getAudience().get(0));
        Assertions.assertArrayEquals(roles, decodedJWT.getClaim(Const.CLAIM_ROLES).asArray(String.class));
    }

    @Test
    void invalidTokenTest() {
        final String token = TestUtil.generateInvalidToken();

        Assertions.assertThrows(JWTVerificationException.class, () -> Token.verify(token));
    }
}

