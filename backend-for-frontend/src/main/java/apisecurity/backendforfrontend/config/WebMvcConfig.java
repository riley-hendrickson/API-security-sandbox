package apisecurity.backendforfrontend.config;

import apisecurity.backendforfrontend.ratelimiting.UserRateLimitInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer
{
    private final UserRateLimitInterceptor userRateLimitInterceptor;

    public WebMvcConfig(UserRateLimitInterceptor userRateLimitInterceptor)
    {
        this.userRateLimitInterceptor = userRateLimitInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry)
    {
        registry.addInterceptor(userRateLimitInterceptor)
                .addPathPatterns("/api/**", "/me");
    }
}
