package apisecurity.backendforfrontend.ratelimit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc; // use the same import as your existing bff tests
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * User tier: a HandlerInterceptor keyed on the OIDC subject, with method-based cost.
 * User capacity 5, writes cost 2, no meaningful refill. The IP tier is set high so it never interferes.
 */
@SpringBootTest(properties = {
        "rate-limit.ip.capacity=1000",
        "rate-limit.ip.refill-tokens=1000",
        "rate-limit.ip.refill-period=1h",
        "rate-limit.user.capacity=5",
        "rate-limit.user.refill-tokens=1",
        "rate-limit.user.refill-period=1h",
        "rate-limit.write-cost=2"
})
@AutoConfigureMockMvc
@Testcontainers
class UserRateLimitTest
{
    private static final int USER_CAPACITY = 5;

    /**
     * A write that the interceptor charges for but that never reaches the relay:
     * the path matches DELETE /api/documents/{documentId}, so preHandle runs and charges
     * the write cost, then converting "not-a-number" to a Long fails and Spring answers 400.
     * That keeps docs-api out of these tests entirely.
     */
    private static final String CHARGED_WRITE = "/api/documents/not-a-number";

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7.2.6-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry)
    {
        registry.add("app.redis.host", redis::getHost);
        registry.add("app.redis.port", () -> redis.getMappedPort(6379));
    }

    @Autowired
    MockMvc mockMvc;

    /** Every test logs in as its own user, so buckets left in Redis by other tests can't interfere. */
    private static RequestPostProcessor asUser(String sub)
    {
        return oidcLogin().idToken(token -> token.subject(sub));
    }

    private static String uniqueSub()
    {
        return "user-" + UUID.randomUUID();
    }

    @Test
    void reads_costOneToken_andRemainingCountsDown() throws Exception
    {
        String sub = uniqueSub();

        for (int remaining = USER_CAPACITY - 1; remaining >= 0; remaining--)
        {
            mockMvc.perform(get("/me").with(asUser(sub)))
                    .andExpect(status().isOk())
                    .andExpect(header().string("X-RateLimit-Remaining", String.valueOf(remaining)));
        }

        mockMvc.perform(get("/me").with(asUser(sub)))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists(HttpHeaders.RETRY_AFTER));
    }

    @Test
    void writes_costMore_andALeftoverTokenStillCoversARead() throws Exception
    {
        String sub = uniqueSub();

        // 5 tokens -> 3 -> 1
        mockMvc.perform(delete(CHARGED_WRITE).with(asUser(sub)).with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-RateLimit-Remaining", "3"));
        mockMvc.perform(delete(CHARGED_WRITE).with(asUser(sub)).with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-RateLimit-Remaining", "1"));

        // 1 token left: not enough for a write (cost 2)...
        mockMvc.perform(delete(CHARGED_WRITE).with(asUser(sub)).with(csrf()))
                .andExpect(status().isTooManyRequests());

        // ...but enough for a read (cost 1). A rejected request spends nothing.
        mockMvc.perform(get("/me").with(asUser(sub)))
                .andExpect(status().isOk())
                .andExpect(header().string("X-RateLimit-Remaining", "0"));
    }

    @Test
    void eachUserHasTheirOwnBucket() throws Exception
    {
        String exhausted = uniqueSub();
        String fresh = uniqueSub();

        for (int i = 0; i < USER_CAPACITY; i++)
        {
            mockMvc.perform(get("/me").with(asUser(exhausted)));
        }
        mockMvc.perform(get("/me").with(asUser(exhausted)))
                .andExpect(status().isTooManyRequests());

        mockMvc.perform(get("/me").with(asUser(fresh)))
                .andExpect(status().isOk());
    }

    @Test
    void requestRejectedBySecurity_neverReachesTheInterceptor() throws Exception
    {
        String sub = uniqueSub();

        // A write without a CSRF token is rejected by Spring Security (403) before the interceptor runs...
        mockMvc.perform(delete(CHARGED_WRITE).with(asUser(sub)))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("X-RateLimit-Remaining"));

        // ...so it cost the user nothing: their bucket is still full.
        mockMvc.perform(get("/me").with(asUser(sub)))
                .andExpect(status().isOk())
                .andExpect(header().string("X-RateLimit-Remaining", String.valueOf(USER_CAPACITY - 1)));
    }
}