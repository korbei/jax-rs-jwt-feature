package com.korbei.rs.jwt.feature;

import com.korbei.rs.jwt.Const;
import com.korbei.rs.jwt.Token;
import org.jboss.weld.junit5.auto.AddPackages;
import org.jboss.weld.junit5.auto.EnableAutoWeld;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

import static org.mockito.Mockito.*;


@EnableAutoWeld
@AddPackages(Token.class)
class AuthenticationFilterTest {

    private ContainerRequestContext ctx = mock(ContainerRequestContext.class);
    private AuthenticationFilter authenticationFilter = new AuthenticationFilter();

    @BeforeEach
    void init() {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.MINUTE, 1);

        final String[] roles = {"admin", "user"};
        final String token = Token.create()
                .withSubject("korbei")
                .withRoles(roles)
                .withExpiresAt(calendar.getTime())
                .withIssuedAt(new Date())
                .sign();

        when(ctx.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(Const.JWT_AUTH_SCHEME + " " + token);
        when(ctx.getSecurityContext()).thenReturn(mock(SecurityContext.class));
        when(ctx.getSecurityContext().isSecure()).thenReturn(true);
    }

    @Test
    void filter() throws IOException {
        authenticationFilter.filter(ctx);

        final ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);

        verify(ctx).setSecurityContext(securityContextCaptor.capture());

        final SecurityContext securityContext = securityContextCaptor.getValue();

        Assertions.assertTrue(securityContext.isUserInRole("admin"));
        Assertions.assertTrue(securityContext.isSecure());
        Assertions.assertEquals("korbei", securityContext.getUserPrincipal().getName());
        Assertions.assertEquals(Const.JWT_AUTH_SCHEME, securityContext.getAuthenticationScheme());
    }

    @Test
    void missingAuthorizationHeaderTest() {
        when(ctx.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        Assertions.assertThrows(NotAuthorizedException.class, () -> authenticationFilter.filter(ctx));
    }

    @Test
    void invalidTokenTest() {
        final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJrb3JiZWkiLCJyb2xlcyI6WyJhZG1pbiIsInVzZXIiXSwi" +
                "aXNzIjoiZWFzeS1qd3QiLCJleHAiOjE1NDkxMTEzNjYsImlhdCI6MTU0OTExMTM2Nn0.Pu_zFVzDOfbbDAFZfEo-rsOGgolYtF8c" +
                "zHfJTx_RX7m6MYF2p3A0np-NPQty-Tf5lZvAQ0NBlu99O6MGXByg3yCU4nal3Ix7FfZhdzaNiVSQXpXVnKW3x3-Lj3_14NUVmO9c" +
                "1A3_pC_IcJAUsvqeCuqYjxTFm0aVQkxWaOtP4Tk";
        when(ctx.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(Const.JWT_AUTH_SCHEME + " " + token);
        Assertions.assertThrows(NotAuthorizedException.class, () -> authenticationFilter.filter(ctx));
    }
}