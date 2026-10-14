package apisecurity.backendforfrontend.controllers;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController
{
    public record MeResponse(String sub, String preferredUsername, String email) {}

    @GetMapping("/me")
    public MeResponse me(@AuthenticationPrincipal OidcUser user)
    {
        return new MeResponse(user.getSubject(), user.getPreferredUsername(), user.getEmail());
    }
}
