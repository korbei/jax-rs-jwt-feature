package com.korbei.rs.jwt.feature;


import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.reflect.Method;

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
}

