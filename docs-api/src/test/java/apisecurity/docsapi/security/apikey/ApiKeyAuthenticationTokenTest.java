package apisecurity.docsapi.security.apikey;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApiKeyAuthenticationTokenTest
{
    private static final String RAW_KEY = "dk_active01_secret";

    @Test
    void unauthenticatedToken_holdsOnlyTheRawKey()
    {
        ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.unauthenticated(RAW_KEY);

        assertThat(token.isAuthenticated()).isFalse();
        assertThat(token.getCredentials()).isEqualTo(RAW_KEY);
        assertThat(token.getPrincipal()).isNull();
        assertThat(token.getKeyId()).isNull();
        assertThat(token.getAuthorities()).isEmpty();
    }

    @Test
    void authenticatedToken_holdsIdentity_andNoSecret()
    {
        ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.authenticated(
                "reporting-tool", "active01", List.of(new SimpleGrantedAuthority("internal:reports:read")));

        assertThat(token.isAuthenticated()).isTrue();
        assertThat(token.getCredentials()).isNull();
        assertThat(token.getName()).isEqualTo("reporting-tool");
        assertThat(token.getKeyId()).isEqualTo("active01");
        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("internal:reports:read");
    }

    @Test
    void unauthenticatedToken_cannotBePromoted()
    {
        ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.unauthenticated(RAW_KEY);

        assertThatThrownBy(() -> token.setAuthenticated(true))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(token.isAuthenticated()).isFalse();
    }

    @Test
    void authenticatedToken_canBeDowngraded()
    {
        ApiKeyAuthenticationToken token = ApiKeyAuthenticationToken.authenticated(
                "reporting-tool", "active01", List.of());

        token.setAuthenticated(false);

        assertThat(token.isAuthenticated()).isFalse();
    }
}