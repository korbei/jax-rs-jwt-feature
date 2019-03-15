package com.korbei.rs.jwt.feature;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.korbei.rs.jwt.Const;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

public class JwtSecurityContext implements SecurityContext {
    private final DecodedJWT decodedJWT;
    private final boolean isSecure;

    JwtSecurityContext(final DecodedJWT decodedJWT, final boolean isSecure) {
        this.decodedJWT = decodedJWT;
        this.isSecure = isSecure;
    }

    public DecodedJWT getDecodedJWT() {
        return decodedJWT;
    }

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
}
