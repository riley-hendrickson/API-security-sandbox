package apisecurity.docsapi.entities;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "api_keys")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ApiKey
{
    @Id
    private String keyId;
    @Column(nullable = false)
    private String clientName;
    @Column(nullable = false)
    private String keyHash;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> authorities;
    @Column(nullable = false)
    private Instant createdAt;
    private Instant expiresAt;
    private Instant revokedAt;

    public ApiKey(String keyId, String clientName, String keyHash, Set<String> authorities, Instant createdAt, Instant expiresAt)
    {
        this.keyId = keyId;
        this.clientName = clientName;
        this.keyHash = keyHash;
        this.authorities = authorities;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }

    public void revoke(Instant when)
    {
        this.revokedAt = when;
    }
}
