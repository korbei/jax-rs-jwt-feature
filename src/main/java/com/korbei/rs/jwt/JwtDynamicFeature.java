package com.korbei.rs.jwt;


import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.*;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.Objects;

public class JwtDynamicFeature implements DynamicFeature {
    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        final Method method = resourceInfo.getResourceMethod();

        // DenyAll on the method take precedence over RolesAllowed and PermitAll
        if (method.isAnnotationPresent(DenyAll.class)) {
            context.register(new AuthenticationFilter());
            context.register(new AuthorizationFilter());
            return;
        }

        // RolesAllowed on the method takes precedence over PermitAll
        RolesAllowed roles = method.getAnnotation(RolesAllowed.class);
        if (roles != null) {
            context.register(new AuthenticationFilter());
            context.register(new AuthorizationFilter(roles.value()));
            return;
        }

        // PermitAll takes precedence over RolesAllowed on the class
        if (method.isAnnotationPresent(PermitAll.class)) {
            context.register(new AuthenticationFilter());
            return;
        }

        final Class<?> resourceClass = resourceInfo.getResourceClass();

        // DenyAll can't be attached to classes

        // RolesAllowed on the class takes precedence over PermitAll
        roles = resourceClass.getAnnotation(RolesAllowed.class);
        if (roles != null) {
            context.register(new AuthenticationFilter());
            context.register(new AuthorizationFilter(roles.value()));
            return;
        }

        // @PermitAll on the class
        if (resourceClass.isAnnotationPresent(PermitAll.class)) {
            context.register(new AuthenticationFilter());
        }
    }

    @PreMatching
    @Priority(Priorities.AUTHENTICATION)
    private static class AuthenticationFilter implements ContainerRequestFilter {

        @Override
        public void filter(ContainerRequestContext ctx) throws IOException {
            final String authorizationHeader = ctx.getHeaderString(HttpHeaders.AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith(Const.JWT_AUTH_SCHEME)) {
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
    }

    @Priority(Priorities.AUTHORIZATION)
    private static class AuthorizationFilter implements ContainerRequestFilter {
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
}

