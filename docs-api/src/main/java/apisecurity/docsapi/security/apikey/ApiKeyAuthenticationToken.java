package apisecurity.docsapi.security.apikey;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken
{
    private final String rawKey;
    private final String clientName;
    private final String keyId;

    private ApiKeyAuthenticationToken(String rawKey)
    {
        super(Collections.emptyList());
        this.rawKey = rawKey;
        this.clientName = null;
        this.keyId = null;
        super.setAuthenticated(false);
    }

    private ApiKeyAuthenticationToken(String clientName, String keyId, Collection<? extends GrantedAuthority> authorities)
    {
        super(authorities);
        this.rawKey = null;
        this.clientName = clientName;
        this.keyId = keyId;
        super.setAuthenticated(true);
    }

    public static ApiKeyAuthenticationToken unauthenticated(String rawKey)
    {
        return new ApiKeyAuthenticationToken(rawKey);
    }

    public static ApiKeyAuthenticationToken authenticated(String clientName, String keyId, Collection<? extends GrantedAuthority> authorities)
    {
        return new ApiKeyAuthenticationToken(clientName, keyId, authorities);
    }

    public String getKeyId(){ return this.keyId; }


    @Override
    public @Nullable Object getCredentials()
    {
        return this.rawKey;
    }

    @Override
    public @Nullable Object getPrincipal()
    {
        return this.clientName;
    }

    @Override
    public void setAuthenticated(boolean authenticated)
    {
        if(authenticated) throw new IllegalArgumentException("Cannot mark this token as authenticated; use ApiKeyAuthenticationToken.authenticated(...)");

        super.setAuthenticated(false);
    }
}
