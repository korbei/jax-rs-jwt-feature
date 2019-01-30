package com.korbei.rs.jwt.configuration;

import org.jboss.weld.junit5.auto.AddPackages;
import org.jboss.weld.junit5.auto.EnableAutoWeld;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.enterprise.inject.Any;
import javax.inject.Inject;
import java.util.Optional;

@EnableAutoWeld
@AddPackages(DefaultJwtConfigurationProvider.class)
public class DefaultJwtConfigurationProviderTest {

    @Inject @Any
    JwtConfigurationProvider provider;

    @Test
    public void defaultConfigurationTest() {
        Assertions.assertEquals(Optional.empty(), provider.getAcceptLeeway());
        Assertions.assertEquals("easy-jwt", provider.getIssuer());
        Assertions.assertArrayEquals(new String[]{"easy-jwt"}, provider.getAudience());
        Assertions.assertEquals("RS256", provider.getAlgorithm().getName());
    }
}

