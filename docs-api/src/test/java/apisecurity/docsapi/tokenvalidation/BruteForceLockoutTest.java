package apisecurity.docsapi.tokenvalidation;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proves Keycloak's brute-force detection against the realm config in realm-export.json.
 *
 * Uses a dedicated user that no other test touches: the lockout outlives this test because
 * the Keycloak container is shared across every class extending KeycloakIntegrationTest.
 *
 * Needs no Spring context: it talks to Keycloak directly.
 */
class BruteForceLockoutTest extends KeycloakIntegrationTest
{
    private static final String REALM = "sandbox";
    private static final String USERNAME = "lockout-target";
    private static final String PASSWORD = "lockout-target";

    // Must match failureFactor in realm-export.json
    private static final int FAILURE_FACTOR = 25;

    // Failures closer together than quickLoginCheckMilliSeconds (1000) trigger the quick-login rule
    // instead. Spacing them out makes this test prove the failure-count threshold itself.
    private static final long SPACING_MS = 1_100;

    private record TokenResult(HttpStatusCode status, Map<?, ?> body)
    {
        boolean issuedToken()
        {
            return status.is2xxSuccessful() && body != null && body.get("access_token") != null;
        }
    }

    /** Like tokenFor, but returns failures instead of throwing on them. */
    private static TokenResult attemptLogin(String password)
    {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", "dev-test-client");
        form.add("client_secret", DEV_TEST_CLIENT_SECRET);
        form.add("username", USERNAME);
        form.add("password", password);

        return RestClient.create()
                .post()
                .uri(realmUrl() + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .exchange((request, response) ->
                        new TokenResult(response.getStatusCode(), response.bodyTo(Map.class)));
    }

    @Test
    void realmHasBruteForceProtectionConfigured()
    {
        try (Keycloak admin = KEYCLOAK.getKeycloakAdminClient())
        {
            RealmRepresentation realm = admin.realm(REALM).toRepresentation();

            assertThat(realm.isBruteForceProtected()).isTrue();
            assertThat(realm.getFailureFactor()).isEqualTo(FAILURE_FACTOR);
        }
    }

    @Test
    void repeatedWrongPasswords_lockTheAccount_soEvenTheCorrectPasswordIsRefused() throws InterruptedException
    {
        // Positive control: the seeded user can log in. Without this, a typo in the seeded
        // password would make the final assertion pass for the wrong reason.
        assertThat(attemptLogin(PASSWORD).issuedToken())
                .as("positive control: correct password works before the attack")
                .isTrue();

        for (int attempt = 1; attempt <= FAILURE_FACTOR; attempt++)
        {
            TokenResult result = attemptLogin("wrong-password-" + attempt);
            assertThat(result.status().is4xxClientError())
                    .as("wrong password attempt %d is rejected", attempt)
                    .isTrue();
            Thread.sleep(SPACING_MS);
        }

        // The correct password is now refused, from the outside indistinguishable from a wrong one
        TokenResult afterAttack = attemptLogin(PASSWORD);
        assertThat(afterAttack.issuedToken()).isFalse();
        assertThat(afterAttack.status().is4xxClientError()).isTrue();

        // And Keycloak's own records agree on why: the account is disabled by brute-force detection
        try (Keycloak admin = KEYCLOAK.getKeycloakAdminClient())
        {
            RealmResource realm = admin.realm(REALM);
            String userId = realm.users().search(USERNAME, true).getFirst().getId();
            Map<String, Object> status = realm.attackDetection().bruteForceUserStatus(userId);

            assertThat(status.get("disabled")).isEqualTo(true);
        }
    }
}