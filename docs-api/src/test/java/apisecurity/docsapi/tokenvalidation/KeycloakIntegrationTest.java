package apisecurity.docsapi.tokenvalidation;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

abstract class KeycloakIntegrationTest
{

    static final String ALICE = "11111111-1111-1111-1111-111111111111";
    static final String BOB   = "22222222-2222-2222-2222-222222222222";

    static final String DEV_TEST_CLIENT_SECRET = "a0DtOfZtv4A0OYfgdpZndf3JTnAKkmKgRY4TTqxahy0OEl5OVlSEf0Quo5krJNrBAB4gCpeWCCJUflDpUYHjQR";
    static final String OTHER_CLIENT_SECRET    = "SHCDVqdo13NaDnfbyNw0xtdBmmC1B5SNRqVE6Ty6n3zDKVcn3leNIIGQrixeblKOaqcCxsMnEVpFvJl1KM4wxO";

    static final KeycloakContainer KEYCLOAK =
            new KeycloakContainer("quay.io/keycloak/keycloak:26.7.4")
                    .withRealmImportFile("realm-export.json");

    static
    {
        KEYCLOAK.start();
    }

    static String realmUrl()
    {
        return KEYCLOAK.getAuthServerUrl() + "/realms/sandbox";
    }

    @DynamicPropertySource
    static void keycloakProperties(DynamicPropertyRegistry registry)
    {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri",
                KeycloakIntegrationTest::realmUrl);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> realmUrl() + "/protocol/openid-connect/certs");
    }

    static String tokenFor(String clientId, String clientSecret, String username, String password)
    {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("username", username);
        form.add("password", password);

        Map<?, ?> response = RestClient.create()
                .post()
                .uri(realmUrl() + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        return (String) response.get("access_token");
    }

    static String aliceToken()
    {
        return tokenFor("dev-test-client", DEV_TEST_CLIENT_SECRET, "alice", "alice");
    }
}