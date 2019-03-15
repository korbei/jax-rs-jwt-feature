package com.korbei.rs.jwt.feature;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.korbei.rs.jwt.Const;
import com.korbei.rs.jwt.TestUtil;
import com.korbei.rs.jwt.Token;
import org.jboss.weld.junit5.auto.AddPackages;
import org.jboss.weld.junit5.auto.EnableAutoWeld;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@EnableAutoWeld
@AddPackages(Token.class)
class JwtSecurityContextTest {

    @Test
    void securityContextTest() {
        final String token = TestUtil.generateToken();
        final DecodedJWT decodedJWT = Token.verify(token);

        final JwtSecurityContext jwtSecurityContext = new JwtSecurityContext(decodedJWT, true);

        Assertions.assertTrue(jwtSecurityContext.isSecure());
        Assertions.assertEquals(Const.JWT_AUTH_SCHEME, jwtSecurityContext.getAuthenticationScheme());
        Assertions.assertTrue(jwtSecurityContext.isUserInRole("admin"));
        Assertions.assertTrue(jwtSecurityContext.isUserInRole("user"));
        Assertions.assertFalse(jwtSecurityContext.isUserInRole("superuser"));
        Assertions.assertEquals("korbei", jwtSecurityContext.getUserPrincipal().getName());
        Assertions.assertEquals(decodedJWT, jwtSecurityContext.getDecodedJWT());

    }
}
