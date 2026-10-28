package apisecurity.docsapi.security.apikey;

import apisecurity.docsapi.repositories.ApiKeyRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
public class ApiKeyFilterChainConfig
{
    @Bean
    @Order(1)
    SecurityFilterChain apiKeyFilterChain(HttpSecurity http, ApiKeyRepository apiKeyRepository) throws Exception
    {
        AuthenticationManager authenticationManager = new ProviderManager(new ApiKeyAuthenticationProvider(apiKeyRepository));
        AuthenticationEntryPoint unauthorizedEntryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

        ApiKeyAuthenticationFilter apiKeyAuthenticationFilter = new ApiKeyAuthenticationFilter(authenticationManager, unauthorizedEntryPoint);

        http
                .securityMatcher("/internal/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e.authenticationEntryPoint(unauthorizedEntryPoint))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/internal/reports/**").hasAuthority("internal:reports:read")
                        .anyRequest().denyAll())
                .addFilterBefore(apiKeyAuthenticationFilter, AnonymousAuthenticationFilter.class);
        return http.build();
    }
}
