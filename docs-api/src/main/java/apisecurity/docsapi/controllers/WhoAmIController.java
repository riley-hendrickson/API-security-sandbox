package apisecurity.docsapi.controllers;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class WhoAmIController
{
    @GetMapping("/whoami")
    public Map<String, Object> whoAmI(Authentication authentication)
    {
        return Map.of(
                "name", authentication.getName(),
                "authorities", authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList());
    }
}
