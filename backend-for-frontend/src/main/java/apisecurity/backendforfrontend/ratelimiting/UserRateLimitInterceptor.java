package apisecurity.backendforfrontend.config;

import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.nio.charset.StandardCharsets;

@Component
public class UserRateLimitInterceptor implements HandlerInterceptor
{
    private final LettuceBasedProxyManager<byte[]> proxyManager;
    private final BucketConfiguration userBucketConfiguration;
    private final RateLimitProperties rateLimitProperties;

    private final Logger log = LoggerFactory.getLogger(UserRateLimitInterceptor.class);

    public UserRateLimitInterceptor(LettuceBasedProxyManager<byte[]> proxyManager,
                                    @Qualifier("userBucketConfiguration") BucketConfiguration userBucketConfiguration,
                                    RateLimitProperties rateLimitProperties)
    {
        this.proxyManager = proxyManager;
        this.userBucketConfiguration = userBucketConfiguration;
        this.rateLimitProperties = rateLimitProperties;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception
    {
        Authentication authentication = SecurityContextHolder.getContextHolderStrategy().getContext().getAuthentication();

        if(!(authentication != null && authentication.getPrincipal() instanceof OidcUser user))
        {
            return true;
        }
        String sub = user.getSubject();

        long cost = switch(request.getMethod())
        {
            case "GET", "HEAD", "OPTIONS" -> 1;
            default -> rateLimitProperties.writeCost();
        };

        byte[] key = ("rl:user:" + sub).getBytes(StandardCharsets.UTF_8);
        ConsumptionProbe probe;
        try
        {
            probe = proxyManager.builder()
                    .build(key, () -> userBucketConfiguration)
                    .tryConsumeAndReturnRemaining(cost);
        }
        catch(RuntimeException e)
        {
            log.warn("Rate limiter unavailable, allowing request");
            return true;
        }

        if(probe.isConsumed())
        {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
            return true;
        }
        else
        {
            long retryAfterSeconds = Math.max(1, (probe.getNanosToWaitForRefill() + 999_999_999) / 1_000_000_000);
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
            response.sendError(429, "Rate limit exceeded");
            return false;
        }
    }
}
