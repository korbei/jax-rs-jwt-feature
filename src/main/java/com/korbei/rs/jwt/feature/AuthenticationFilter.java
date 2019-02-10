package com.korbei.rs.jwt.feature;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.korbei.rs.jwt.Const;
import com.korbei.rs.jwt.Token;

import javax.annotation.Priority;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.Principal;

@PreMatching
@Priority(Priorities.AUTHENTICATION)
class AuthenticationFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        final String authorizationHeader = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader == null || !authorizationHeader.startsWith(Const.JWT_AUTH_SCHEME)) {
            throw new NotAuthorizedException(Const.JWT_AUTH_SCHEME);
        }

        try {
            final String token = authorizationHeader.substring(7);
            final DecodedJWT decodedJWT = Token.verify(token);
            final boolean isSecure = ctx.getSecurityContext().isSecure();

            ctx.setSecurityContext(new SecurityContext() {
                @Override
                public Principal getUserPrincipal() {
                    return decodedJWT::getSubject;
                }

                @Override
                public boolean isUserInRole(String role) {
                    return decodedJWT
                            .getClaim(Const.CLAIM_ROLES)
                            .asList(String.class)
                            .contains(role);
                }

                @Override
                public boolean isSecure() {
                    return isSecure;
                }

                @Override
                public String getAuthenticationScheme() {
                    return Const.JWT_AUTH_SCHEME;
                }
            });
        } catch (JWTVerificationException e) {
            throw new NotAuthorizedException(Const.JWT_AUTH_SCHEME);
        }
    }
}
