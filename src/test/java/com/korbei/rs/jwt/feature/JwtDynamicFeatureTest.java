package com.korbei.rs.jwt.feature;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import static org.mockito.Mockito.*;


class JwtDynamicFeatureTest {

    private ResourceInfo resourceInfo = mock(ResourceInfo.class);
    private FeatureContext context = mock(FeatureContext.class);
    private JwtDynamicFeature jwtDynamicFeature = new JwtDynamicFeature();

    @BeforeEach
    void init() {
        when(resourceInfo.getResourceMethod()).thenReturn(mock(Method.class));
        when(context.register(ArgumentMatchers.any(ContainerRequestFilter.class))).thenReturn(null);
    }

    @Test
    void denyAllTest() {
        when(resourceInfo.getResourceMethod().isAnnotationPresent(DenyAll.class)).thenReturn(true);

        jwtDynamicFeature.configure(resourceInfo, context);

        verify(context, times(2)).register(ArgumentMatchers.any(ContainerRequestFilter.class));
    }

    @Test
    void rolesAllowedTest() throws NoSuchFieldException, IllegalAccessException {
        final RolesAllowed rolesAllowed = mock(RolesAllowed.class);
        final ArgumentCaptor<ContainerRequestFilter> allowedArgumentCaptor = ArgumentCaptor.forClass(ContainerRequestFilter.class);

        when(rolesAllowed.value()).thenReturn(new String[] {"admin", "user"});
        when(resourceInfo.getResourceMethod().getAnnotation(RolesAllowed.class)).thenReturn(rolesAllowed);

        jwtDynamicFeature.configure(resourceInfo, context);

        verify(context, times(2)).register(allowedArgumentCaptor.capture());

        final AuthorizationFilter authorizationFilter = (AuthorizationFilter)allowedArgumentCaptor.getAllValues().get(1);
        final Field rolesAllowedField = AuthorizationFilter.class.getDeclaredField("rolesAllowed");
        rolesAllowedField.setAccessible(true);

        final String[] roles = (String[]) rolesAllowedField.get(authorizationFilter);

        Assertions.assertEquals("admin", roles[0]);
        Assertions.assertEquals("user", roles[1]);
    }

    @Test
    void permitAllTest() {
        when(resourceInfo.getResourceMethod().isAnnotationPresent(PermitAll.class)).thenReturn(true);

        jwtDynamicFeature.configure(resourceInfo, context);

        verify(context, times(1)).register(ArgumentMatchers.any(ContainerRequestFilter.class));
    }

    @Test
    void rolesAllowedOnClassTest() throws NoSuchFieldException, IllegalAccessException {
        doReturn(mock(Foo.class).getClass()).when(resourceInfo).getResourceClass();

        final ArgumentCaptor<ContainerRequestFilter> allowedArgumentCaptor = ArgumentCaptor.forClass(ContainerRequestFilter.class);

        jwtDynamicFeature.configure(resourceInfo, context);
        verify(context, times(2)).register(allowedArgumentCaptor.capture());

        final AuthorizationFilter authorizationFilter = (AuthorizationFilter)allowedArgumentCaptor.getAllValues().get(1);
        final Field rolesAllowedField = AuthorizationFilter.class.getDeclaredField("rolesAllowed");
        rolesAllowedField.setAccessible(true);

        final String[] roles = (String[]) rolesAllowedField.get(authorizationFilter);

        Assertions.assertEquals("admin", roles[0]);
        Assertions.assertEquals("user", roles[1]);
    }

    @Test
    void permitAllOnClassTest() {
        doReturn(mock(Bar.class).getClass()).when(resourceInfo).getResourceClass();

        jwtDynamicFeature.configure(resourceInfo, context);

        verify(context, times(1)).register(ArgumentMatchers.any(ContainerRequestFilter.class));
    }

    @RolesAllowed({"admin", "user"})
    private class Foo {

    }

    @PermitAll
    private class Bar {

    }
}