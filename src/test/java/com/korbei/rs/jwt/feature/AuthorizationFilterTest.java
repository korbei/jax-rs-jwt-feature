package com.korbei.rs.jwt.feature;

import com.korbei.rs.jwt.Token;
import org.jboss.weld.junit5.auto.AddPackages;
import org.jboss.weld.junit5.auto.EnableAutoWeld;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.Principal;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@EnableAutoWeld
@AddPackages(Token.class)
class AuthorizationFilterTest {
    private ContainerRequestContext ctx = mock(ContainerRequestContext.class);

    @BeforeEach
    void init() {
        when(ctx.getSecurityContext()).thenReturn(mock(SecurityContext.class));
        when(ctx.getSecurityContext().isSecure()).thenReturn(true);
        when(ctx.getSecurityContext().getUserPrincipal()).thenReturn(mock(Principal.class));
    }

    @Test
    void denyAllTest() {
        AuthorizationFilter filter = new AuthorizationFilter();
        Assertions.assertThrows(ForbiddenException.class, () -> filter.filter(ctx));
    }

    @Test
    void unAuthenticatedTest() {
        when(ctx.getSecurityContext().getUserPrincipal()).thenReturn(null);
        AuthorizationFilter filter = new AuthorizationFilter(new String[]{"admin", "user"});
        Assertions.assertThrows(ForbiddenException.class, () -> filter.filter(ctx));
    }

    @Test
    void rolesAllowedTest() throws IOException {
        when(ctx.getSecurityContext().isUserInRole("admin")).thenReturn(true);
        AuthorizationFilter filter = new AuthorizationFilter(new String[]{"admin", "user"});
        filter.filter(ctx);
    }

    @Test
    void rolesNotAllowedTest() throws IOException {
        when(ctx.getSecurityContext().isUserInRole("admin")).thenReturn(false);
        when(ctx.getSecurityContext().isUserInRole("user")).thenReturn(false);
        AuthorizationFilter filter = new AuthorizationFilter(new String[]{"admin", "user"});
        Assertions.assertThrows(ForbiddenException.class, () -> filter.filter(ctx));
    }
}