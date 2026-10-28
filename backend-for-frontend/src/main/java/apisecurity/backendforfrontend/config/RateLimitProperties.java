package apisecurity.backendforfrontend.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "rate-limit")
public record RateLimitProperties(Tier ip, Tier user, long writeCost)
{
    public record Tier(long capacity, long refillTokens, Duration refillPeriod) {}
}
