package apisecurity.docsapi.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.client.RestClient;

@Configuration
public class AuditClientConfig
{
    @Bean
    ClientRegistrationRepository clientRegistrationRepository(
            @Value("${app.keycloak.internal-url}") String internalUrl,
            @Value("${app.docs-api.client-secret}") String clientSecret)
    {
        String tokenUri = internalUrl + "/realms/sandbox/protocol/openid-connect/token";

        ClientRegistration onBehalf = ClientRegistration.withRegistrationId("audit-on-behalf")
                .clientId("docs-api")
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("audit:write")
                .tokenUri(tokenUri)
                .build();

        ClientRegistration system = ClientRegistration.withRegistrationId("audit-system")
                .clientId("docs-api")
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("audit:write")
                .tokenUri(tokenUri)
                .build();

        return new InMemoryClientRegistrationRepository(onBehalf, system);
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(ClientRegistrationRepository registrations)
    {
        TokenExchangeOAuth2AuthorizedClientProvider tokenExchange = new TokenExchangeOAuth2AuthorizedClientProvider();
        tokenExchange.setSubjectTokenResolver(context ->
        {
            if(context.getPrincipal() instanceof JwtAuthenticationToken authenticationToken)
            {
                Jwt jwt = authenticationToken.getToken();
                return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                        jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt());
            }
            return null;
        });

        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .provider(tokenExchange)
                .build();

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                    registrations, new InMemoryOAuth2AuthorizedClientService(registrations));
        manager.setAuthorizedClientProvider(provider);
        return manager;
    }

    @Bean
    RestClient auditOnBehalfClient(OAuth2AuthorizedClientManager authorizedClientManager,
                                  @Value("${AUDIT_SERVICE_URL:http://localhost:8080}") String auditServiceUrl)
    {
        OAuth2ClientHttpRequestInterceptor requestInterceptor = new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
        requestInterceptor.setClientRegistrationIdResolver(request -> "audit-on-behalf");

        return RestClient.builder()
                .requestInterceptor(requestInterceptor)
                .baseUrl(auditServiceUrl)
                .build();
    }
}
