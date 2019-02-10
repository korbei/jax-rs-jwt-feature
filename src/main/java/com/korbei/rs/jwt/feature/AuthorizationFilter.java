package com.korbei.rs.jwt.feature;

import com.korbei.rs.jwt.Const;

import javax.annotation.Priority;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import java.io.IOException;
import java.util.Objects;

@Priority(Priorities.AUTHORIZATION)
class AuthorizationFilter implements ContainerRequestFilter {
    private final boolean denyAll;
    private final String[] rolesAllowed;

    AuthorizationFilter() {
        this.denyAll = true;
        this.rolesAllowed = null;
    }

    AuthorizationFilter(final String[] rolesAllowed) {
        this.denyAll = false;
        this.rolesAllowed = (rolesAllowed != null) ? rolesAllowed : new String[] {};
    }

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if(denyAll || (rolesAllowed.length > 0 && !isAuthenticated(requestContext))) {
            throw new ForbiddenException(Const.JWT_AUTH_SCHEME);
        }

        for (final String role : rolesAllowed) {
            if (requestContext.getSecurityContext().isUserInRole(role)) {
                return;
            }
        }

        throw new ForbiddenException(Const.JWT_AUTH_SCHEME);
    }

    private static boolean isAuthenticated(final ContainerRequestContext requestContext) {
        return Objects.nonNull(requestContext.getSecurityContext().getUserPrincipal());
    }
}
