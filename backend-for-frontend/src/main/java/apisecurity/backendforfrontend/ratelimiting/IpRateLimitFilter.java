package apisecurity.backendforfrontend.ratelimiting;

import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class IpRateLimitFilter extends OncePerRequestFilter
{
    private final LettuceBasedProxyManager<byte[]> proxyManager;
    private final BucketConfiguration ipBucketConfiguration;

    private static final Logger log = LoggerFactory.getLogger(IpRateLimitFilter.class);

    public IpRateLimitFilter(LettuceBasedProxyManager<byte[]> proxyManager,
                             @Qualifier("ipBucketConfiguration") BucketConfiguration ipBucketConfiguration)
    {
        this.proxyManager = proxyManager;
        this.ipBucketConfiguration = ipBucketConfiguration;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        // build the key:
        byte[] key = ("rl:ip:" + request.getRemoteAddr()).getBytes(StandardCharsets.UTF_8);
        ConsumptionProbe probe;
        try
        {
            probe = proxyManager.builder()
                    .build(key, () -> ipBucketConfiguration)
                    .tryConsumeAndReturnRemaining(1);
        }
        catch (RuntimeException e)
        {
            log.warn("Rate limiter unavailable, allowing request. " + e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        if(probe.isConsumed())
        {
            filterChain.doFilter(request, response);
        }
        else
        {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            long retryAfterSeconds = Math.max(1, (probe.getNanosToWaitForRefill() + 999_999_999) / 1_000_000_000);
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        }
    }
}
