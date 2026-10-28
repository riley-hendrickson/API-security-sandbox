package apisecurity.backendforfrontend.config;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
public class RedisClientConfig
{
    @Bean(destroyMethod = "shutdown")
    RedisClient redisClient(@Value("${app.redis.host}") String redisHost,
                            @Value("${app.redis.port}") int redisPort)
    {
        RedisURI redisURI = RedisURI.builder()
                .withHost(redisHost)
                .withPort(redisPort)
                .withTimeout(Duration.ofMillis(200))
                .build();
        return RedisClient.create(redisURI);
    }
}
