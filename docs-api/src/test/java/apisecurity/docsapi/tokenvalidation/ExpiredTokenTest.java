package apisecurity.docsapi.tokenvalidation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Clock;
import java.time.Duration;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ExpiredTokenTest extends KeycloakIntegrationTest
{

    @TestConfiguration
    static class ClockAheadConfig
    {
        // 300s token lifetime + 60s default clock skew = 360s; 10 minutes is safely past both
        @Bean
        @Primary
        Clock clockTenMinutesAhead()
        {
            return Clock.offset(Clock.systemUTC(), Duration.ofMinutes(10));
        }
    }

    @Autowired MockMvc mockMvc;

    @Test
    void freshTokenSeenFromTheFuture_isRejectedAsExpired() throws Exception
    {
        mockMvc.perform(get("/documents")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + aliceToken()))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("expired")));
    }
}