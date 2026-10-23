package apisecurity.docsapi.repositories;

import apisecurity.docsapi.entities.ApiKey;
import org.springframework.data.repository.Repository;

import java.util.Optional;

public interface ApiKeyRepository extends Repository<ApiKey, String>
{
    Optional<ApiKey> findApiKeyByKeyId(String keyId);

    ApiKey save(ApiKey apiKey);

    void delete(ApiKey apiKey);
}
