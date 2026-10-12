package apisecurity.backendforfrontend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import java.util.Map;

@Configuration
public class OAuth2ClientConfig
{
    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
            @Value("${app.keycloak.public-url}") String publicUrl,
            @Value("${app.keycloak.internal-url}") String internalUrl,
            @Value("${app.bff.client-secret}") String clientSecret)
    {
        String realm = "/realms/sandbox";
        String oidc = realm + "/protocol/openid-connect";

        ClientRegistration keycloak = ClientRegistration.withRegistrationId("keycloak")
                .clientId("bff")
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                // browser-facing: browser is redirected here:
                .authorizationUri(publicUrl + oidc + "/auth")
                // server-to-server: bff calls these itself
                .tokenUri(internalUrl + oidc + "/token")
                .jwkSetUri(internalUrl + oidc + "/certs")
                .userNameAttributeName(IdTokenClaimNames.SUB)
                // what the id token's iss must equal, we want to set this without triggering discovery
                .issuerUri(publicUrl + realm)
                // used by RP initiated logout, browser-facing, so use the public url:
                .providerConfigurationMetadata(Map.of(
                        "end_session_endpoint", publicUrl + oidc + "/logout"))
                .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                .build();
        return new InMemoryClientRegistrationRepository(keycloak);
    }
}
