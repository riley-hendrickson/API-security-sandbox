package apisecurity.backendforfrontend.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class SecurityConfig
{
    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity, ClientRegistrationRepository clientRegistrationRepository, @Value("${app.demo.csrf-enabled}") boolean csrfEnabled) throws Exception
    {
        if (!csrfEnabled)
        {
            log.warn("!!! CSRF PROTECTION DISABLED (demo mode). Never run like this outside the demo  !!!");
        }

        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");

        httpSecurity.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated())
                .logout(logout ->
                        logout.logoutSuccessHandler(logoutSuccessHandler)
                                .deleteCookies("JSESSIONID"))
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                        PathPatternRequestMatcher.withDefaults().matcher("/api/**")))
                .csrf(csrf ->
                {
                    if(csrfEnabled) csrf.spa();
                    else csrf.disable();
                })
                .oauth2Login(Customizer.withDefaults());

        return httpSecurity.build();
    }
}
