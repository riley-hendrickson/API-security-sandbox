package apisecurity.docsapi.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakRealmRolesConverterTest
{

    private final KeycloakRealmRolesConverter converter = new KeycloakRealmRolesConverter();

    private static Jwt.Builder baseJwt()
    {
        return Jwt.withTokenValue("unused").header("alg", "RS256").subject("someone");
    }

    @Test
    void mapsRealmRolesToUppercasedRoleAuthorities()
    {
        Jwt jwt = baseJwt()
                .claim("realm_access", Map.of("roles", List.of("user", "admin")))
                .build();

        assertThat(converter.convert(jwt))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    void missingRealmAccess_yieldsNoRoles()
    {
        assertThat(converter.convert(baseJwt().build())).isEmpty();
    }

    @Test
    void malformedRoles_yieldsNoRoles()
    {
        Jwt jwt = baseJwt()
                .claim("realm_access", Map.of("roles", "admin"))
                .build();

        assertThat(converter.convert(jwt)).isEmpty();
    }
}