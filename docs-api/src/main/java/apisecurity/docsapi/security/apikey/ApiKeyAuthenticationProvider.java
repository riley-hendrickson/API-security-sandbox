package apisecurity.docsapi.security.apikey;

import apisecurity.docsapi.entities.ApiKey;
import apisecurity.docsapi.repositories.ApiKeyRepository;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import utils.ApiKeys;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

public class ApiKeyAuthenticationProvider implements AuthenticationProvider
{
    private static final Logger log = LoggerFactory.getLogger(ApiKeyAuthenticationProvider.class);
    private final ApiKeyRepository apiKeyRepository;

    public ApiKeyAuthenticationProvider(ApiKeyRepository apiKeyRepository)
    {
        this.apiKeyRepository = apiKeyRepository;
    }

    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException
    {
        ApiKeys.ParsedApiKey userApiKey = ApiKeys.parse((String) authentication.getCredentials()).orElse(null);
        if(userApiKey == null)
        {
            log.warn("Malformed API key");
            throw new BadCredentialsException("Invalid API key");
        }

        ApiKey storedApiKey = apiKeyRepository.findApiKeyByKeyId(userApiKey.keyId()).orElse(null);
        if(storedApiKey == null)
        {
            log.warn("API key not found: {}", userApiKey.keyId());
            throw new BadCredentialsException("Invalid API key");
        }

        if(!ApiKeys.matches(userApiKey.secret(), storedApiKey.getKeyHash()))
        {
            log.warn("API key does not match: {}", userApiKey.keyId());
            throw new BadCredentialsException("Invalid API key");
        }

        if(storedApiKey.getRevokedAt() != null)
        {
            log.warn("API key has been revoked: {}", userApiKey.keyId());
            throw new BadCredentialsException("Invalid API key");
        }
        if(storedApiKey.getExpiresAt() != null && storedApiKey.getExpiresAt().isBefore(Instant.now()))
        {
            log.warn("API key has expired: {}", userApiKey.keyId());
            throw new BadCredentialsException("Invalid API key");
        }

        Set<GrantedAuthority> authorities = storedApiKey.getAuthorities().stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
        return ApiKeyAuthenticationToken.authenticated(storedApiKey.getClientName(), storedApiKey.getKeyId(), authorities);
    }

    @Override
    public boolean supports(@NonNull Class<?> authentication)
    {
        return ApiKeyAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
