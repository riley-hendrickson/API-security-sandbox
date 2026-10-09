package apisecurity.docsapi;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Map;

public class KeycloakRealmRolesConverter implements Converter<Jwt, Collection<GrantedAuthority>>
{
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt)
    {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        
    }
}
