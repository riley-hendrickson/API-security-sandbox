package apisecurity.auditservice.security;

import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Clock;
import java.util.List;

@Configuration
public class SecurityConfig
{
    @Bean
    Clock clock()
    {
        return Clock.systemUTC();
    }

    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
            @Value("${spring.security.oauth2.resourceserver.jwt.audiences[0]}") String expectedAudience,
            Clock clock)
    {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        // Configure timestamp validator with injected clock
        JwtTimestampValidator timestampValidator = new JwtTimestampValidator();
        timestampValidator.setClock(clock);

        // Configure audience validator
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD,
                aud -> aud!= null && aud.contains(expectedAudience));

        // chain validators together
        OAuth2TokenValidator<Jwt> combinedValidator = new DelegatingOAuth2TokenValidator<>(
                timestampValidator,
                new JwtIssuerValidator(issuerUri),
                audienceValidator);

        decoder.setJwtValidator(combinedValidator);
        return decoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/audit-events").access(AuthorizationManagers.allOf(
                        AuthorityAuthorizationManager.hasAuthority("SCOPE_audit:write"),
                        (authentication, context) -> new AuthorizationDecision(
                                authentication.get() instanceof JwtAuthenticationToken token
                                        && "docs-api".equals(token.getToken().getClaimAsString("azp")))))
                                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                                .anyRequest().denyAll())
                .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
        ;
        return http.build();
    }
}
