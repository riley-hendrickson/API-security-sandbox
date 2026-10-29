package apisecurity.backendforfrontend.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.redis.lettuce.Bucket4jLettuce;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.security.autoconfigure.web.servlet.SecurityFilterProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
public class RateLimitingConfig
{
    @Bean
    BucketConfiguration ipBucketConfiguration(RateLimitProperties rateLimitProperties)
    {
        RateLimitProperties.Tier tier = rateLimitProperties.ip();

        return BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(tier.capacity())
                        .refillGreedy(tier.refillTokens(), tier.refillPeriod())
                        .build())
                .build();
    }

    @Bean
    BucketConfiguration userBucketConfiguration(RateLimitProperties rateLimitProperties)
    {
        RateLimitProperties.Tier tier = rateLimitProperties.user();

        return BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(tier.capacity())
                        .refillGreedy(tier.refillTokens(), tier.refillPeriod())
                        .build())
                .build();
    }

    @Bean
    public LettuceBasedProxyManager<byte[]> proxyManager(RedisClient redisClient)
    {
        return Bucket4jLettuce.casBasedBuilder(redisClient)
                .expirationAfterWrite(ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(Duration.ofSeconds(10)))
                .build();
    }

    @Bean
    FilterRegistrationBean<IpRateLimitFilter> ipRateLimitFilter(LettuceBasedProxyManager<byte[]> proxyManager,
                                                                @Qualifier("ipBucketConfiguration") BucketConfiguration ipBucketConfiguration)
    {
        FilterRegistrationBean<IpRateLimitFilter> registration = new FilterRegistrationBean<>(new IpRateLimitFilter(proxyManager, ipBucketConfiguration));
        registration.setOrder(SecurityFilterProperties.DEFAULT_FILTER_ORDER - 1);
        return registration;
    }
}
