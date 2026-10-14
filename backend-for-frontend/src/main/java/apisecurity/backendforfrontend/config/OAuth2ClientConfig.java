package apisecurity.backendforfrontend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.web.client.RestClient;

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

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository()
    {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository)
    {
        OAuth2AuthorizedClientProvider authorizedClientProvider =
                OAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .build();

        DefaultOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }

    @Bean
    RestClient docsApiClient(OAuth2AuthorizedClientManager authorizedClientManager, OAuth2AuthorizedClientRepository authorizedClientRepository, @Value("${app.docs-api.url}") String docsApiUrl)
    {
        OAuth2ClientHttpRequestInterceptor requestInterceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        requestInterceptor.setClientRegistrationIdResolver(request -> "keycloak");
        requestInterceptor.setAuthorizationFailureHandler(
                OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClientRepository)
        );

        return RestClient.builder()
                .requestInterceptor(requestInterceptor)
                .baseUrl(docsApiUrl)
                .build();
    }
}
