package com.korbei.rs.jwt;


import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.korbei.rs.jwt.Const;
import com.korbei.rs.jwt.Token;
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
                .withRoles(roles)
                .withExpiresAt(calendar.getTime())
                .withIssuedAt(new Date())
                .withAudience("audience")
                .withJWTId(jwtId)
                .withClaim("claim1", "stringClaim")
                .withClaim("claim2", 1)
                .sign();

        Assertions.assertNotNull(token);

        Token.verify(token);

        final DecodedJWT decodedJWT = Token.decode(token);

        Assertions.assertEquals(jwtId, decodedJWT.getId());
        Assertions.assertEquals("stringClaim", decodedJWT.getClaim("claim1").as(String.class));
        Assertions.assertEquals(Integer.valueOf(1), decodedJWT.getClaim("claim2").as(Integer.class));
        Assertions.assertEquals("korbei", decodedJWT.getSubject());
        Assertions.assertEquals("audience", decodedJWT.getAudience().get(0));
        Assertions.assertArrayEquals(roles, decodedJWT.getClaim(Const.CLAIM_ROLES).asArray(String.class));
    }

    @Test
    void invalidTokenTest() {
        final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJrb3JiZWkiLCJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXSwi" +
                "aXNzIjoiZWFzeS1qd3QiLCJleHAiOjE1NDkxMTEzNjYsImlhdCI6MTU0OTExMTM2Nn0.Pu_zFVzDOfbbDAFZfEo-rsOGgolYtF8c" +
                "zHfJTx_RX7m6MYF2p3A0np-NPQty-Tf5lZvAQ0NBlu99O6MGXByg3yCU4nal3Ix7FfZhdzaNiVSQXpXVnKW3x3-Lj3_14NUVmO9c" +
                "1A3_pC_IcJAUsvqeCuqYjxTFm0aVQkxWaOtP4Tk";

        Assertions.assertThrows(JWTVerificationException.class, () -> Token.verify(token));
    }
}

