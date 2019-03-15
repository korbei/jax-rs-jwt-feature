package com.korbei.rs.jwt.feature;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.korbei.rs.jwt.Const;
import com.korbei.rs.jwt.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import java.io.IOException;

@PreMatching
@Priority(Priorities.AUTHENTICATION)
class AuthenticationFilter implements ContainerRequestFilter {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationFilter.class);

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        final String authorizationHeader = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);

        if(authorizationHeader == null || !authorizationHeader.startsWith(Const.JWT_AUTH_SCHEME)) {
            LOG.error("Missing Authorization header!");
            throw new NotAuthorizedException(Const.JWT_AUTH_SCHEME);
        }

        try {
            final String token = authorizationHeader.substring(7);
            final DecodedJWT decodedJWT = Token.verify(token);
            final boolean isSecure = ctx.getSecurityContext().isSecure();

            ctx.setSecurityContext(new JwtSecurityContext(decodedJWT, isSecure));
        } catch (JWTVerificationException e) {
            LOG.error("JWTVerificationException: {}", e.getMessage());
            throw new NotAuthorizedException(Const.JWT_AUTH_SCHEME);
        }
    }
}
