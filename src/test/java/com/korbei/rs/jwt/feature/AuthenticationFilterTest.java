package com.korbei.rs.jwt.feature;

import com.korbei.rs.jwt.Const;
import com.korbei.rs.jwt.TestUtil;
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

import static org.mockito.Mockito.*;


@EnableAutoWeld
@AddPackages(Token.class)
class AuthenticationFilterTest {

    private ContainerRequestContext ctx = mock(ContainerRequestContext.class);
    private AuthenticationFilter authenticationFilter = new AuthenticationFilter();

    @BeforeEach
    void init() {
        final String token = TestUtil.generateToken();

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
        final String token = TestUtil.generateInvalidToken();
        when(ctx.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(Const.JWT_AUTH_SCHEME + " " + token);
        Assertions.assertThrows(NotAuthorizedException.class, () -> authenticationFilter.filter(ctx));
    }
}