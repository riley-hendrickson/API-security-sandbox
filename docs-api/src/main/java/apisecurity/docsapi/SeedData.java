package apisecurity.docsapi;

import apisecurity.docsapi.entities.ApiKey;
import apisecurity.docsapi.entities.Document;
import apisecurity.docsapi.repositories.ApiKeyRepository;
import apisecurity.docsapi.repositories.DocumentRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import utils.ApiKeys;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

@Component
public class SeedData implements CommandLineRunner
{
    private static final String ALICE = "11111111-1111-1111-1111-111111111111";
    private static final String BOB = "22222222-2222-2222-2222-222222222222";
    private static final Set<String> REPORTS_READ = Set.of("internal:reports:read");

    private final DocumentRepository documentRepo;
    private final ApiKeyRepository apiKeyRepo;
    private final String activeKey;
    private final String revokedKey;
    private final String expiredKey;

    public SeedData(DocumentRepository documentRepo,
                    ApiKeyRepository apiKeyRepo,
                    @Value("${apikeys.dev.active}") String activeKey,
                    @Value("${apikeys.dev.revoked}") String revokedKey,
                    @Value("${apikeys.dev.expired}") String expiredKey)
    {
        this.documentRepo = documentRepo;
        this.apiKeyRepo = apiKeyRepo;
        this.activeKey = activeKey;
        this.revokedKey = revokedKey;
        this.expiredKey = expiredKey;
    }

    @Override
    public void run(String... args)
    {
        documentRepo.save(new Document(ALICE, Set.of(), "Alice's private notes", ""));
        documentRepo.save(new Document(BOB, Set.of(), "Bob's private notes", ""));
        documentRepo.save(new Document(ALICE, Set.of(BOB), "Alice's shared notes with Bob", ""));

        Instant now = Instant.now();
        Instant yesterday = now.minus(1, ChronoUnit.DAYS);

        seedKey(activeKey, "reporting-tool", now, null);

        ApiKey revoked = buildKey(revokedKey, "reporting-tool", now, yesterday);
        revoked.revoke(yesterday);
        apiKeyRepo.save(revoked);

        seedKey(expiredKey, "reporting-tool", now, yesterday);
    }

    private void seedKey(String rawKey, String client, Instant createdAt, Instant expiresAt)
    {
        apiKeyRepo.save(buildKey(rawKey, client, createdAt, expiresAt));
    }

    private ApiKey buildKey(String rawKey, String client, Instant createdAt, Instant expiresAt)
    {
        ApiKeys.ParsedApiKey parsed = ApiKeys.parse(rawKey)
                .orElseThrow(() -> new IllegalStateException("Malformed seed API key in config"));
        return new ApiKey(parsed.keyId(), client, ApiKeys.hash(parsed.secret()),
                REPORTS_READ, createdAt, expiresAt);
    }
}
