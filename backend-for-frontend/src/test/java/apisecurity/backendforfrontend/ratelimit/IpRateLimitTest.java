package apisecurity.backendforfrontend.ratelimit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * IP tier: a servlet filter that runs before Spring Security.
 * Tiny IP limit (5, no meaningful refill); the user tier is set high so it never interferes.
 */

@SpringBootTest(properties = {
        "rate-limit.ip.capacity=5",
        "rate-limit.ip.refill-tokens=1",
        "rate-limit.ip.refill-period=1h",
        "rate-limit.user.capacity=1000",
        "rate-limit.user.refill-tokens=1000",
        "rate-limit.user.refill-period=1h",
        "rate-limit.write-cost=2"
})
@AutoConfigureMockMvc
@Testcontainers
class IpRateLimitTest
{
    private static final int IP_CAPACITY = 5;
    private static final AtomicInteger IP_COUNTER = new AtomicInteger();

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7.2.6-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry)
    {
        // Match whatever property names RedisClientConfig reads
        registry.add("app.redis.host", redis::getHost);
        registry.add("app.redis.port", () -> redis.getMappedPort(6379));
    }

    @Autowired
    MockMvc mockMvc;

    /** Every test gets its own IP, so buckets left in Redis by other tests can't interfere. */
    private static String uniqueIp()
    {
        int n = IP_COUNTER.incrementAndGet();
        return "10.0." + (n / 250) + "." + (n % 250 + 1);
    }

    private static RequestPostProcessor fromIp(String ip)
    {
        return request ->
        {
            request.setRemoteAddr(ip);
            return request;
        };
    }

    @Test
    void requestsUnderTheLimit_reachSecurity_thenTheNextIsRejectedWith429() throws Exception
    {
        String ip = uniqueIp();

        // Unauthenticated /me: Spring Security answers 401, which proves the request got past the limiter
        for (int i = 0; i < IP_CAPACITY; i++)
        {
            mockMvc.perform(get("/me").with(fromIp(ip)))
                    .andExpect(status().isUnauthorized());
        }

        // Bucket empty: the limiter answers before Spring Security ever runs
        mockMvc.perform(get("/me").with(fromIp(ip)))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER))
                .andExpect(header().string(HttpHeaders.RETRY_AFTER, not("0")));
    }

    @Test
    void eachIpHasItsOwnBucket() throws Exception
    {
        String exhaustedIp = uniqueIp();
        String freshIp = uniqueIp();

        for (int i = 0; i < IP_CAPACITY; i++)
        {
            mockMvc.perform(get("/me").with(fromIp(exhaustedIp)));
        }
        mockMvc.perform(get("/me").with(fromIp(exhaustedIp)))
                .andExpect(status().isTooManyRequests());

        mockMvc.perform(get("/me").with(fromIp(freshIp)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void limitedLoginRequest_neverCreatesASession() throws Exception
    {
        String ip = uniqueIp();

        for (int i = 0; i < IP_CAPACITY; i++)
        {
            mockMvc.perform(get("/me").with(fromIp(ip)));
        }

        MvcResult result = mockMvc.perform(get("/oauth2/authorization/keycloak").with(fromIp(ip)))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
    }
}