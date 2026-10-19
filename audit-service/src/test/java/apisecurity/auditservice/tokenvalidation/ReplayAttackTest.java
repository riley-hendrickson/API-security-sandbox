package apisecurity.auditservice.tokenvalidation;

import apisecurity.auditservice.entities.AuditEvent;
import apisecurity.auditservice.enums.CallerKind;
import apisecurity.auditservice.repositories.AuditEventRepository;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ReplayAttackTest
{

    static final String ALICE = "11111111-1111-1111-1111-111111111111";

    static final String DEV_TEST_CLIENT_SECRET = "a0DtOfZtv4A0OYfgdpZndf3JTnAKkmKgRY4TTqxahy0OEl5OVlSEf0Quo5krJNrBAB4gCpeWCCJUflDpUYHjQR";
    static final String DOCS_API_SECRET = "uRM4MOPrXrF1O2e4umRuCAYFCfyaecgBvoOjPrTW8bJPChVj2zhhuAYgGbQC1fs9qY79ajzh6XFxmMfhVlU6Na";

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
                ReplayAttackTest::realmUrl);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> realmUrl() + "/protocol/openid-connect/certs");
    }

    @Autowired
    MockMvc mockMvc;
    @Autowired
    AuditEventRepository auditEventRepository;

    // ---- real tokens from the real Keycloak ----

    private static String requestToken(MultiValueMap<String, String> form)
    {
        Map<?, ?> response = RestClient.create()
                .post()
                .uri(realmUrl() + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);
        return (String) response.get("access_token");
    }

    /**
     * alice's ordinary token, issued for docs-api. This is what an attacker would replay.
     */
    private static String aliceDocsApiToken()
    {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", "dev-test-client");
        form.add("client_secret", DEV_TEST_CLIENT_SECRET);
        form.add("username", "alice");
        form.add("password", "alice");
        return requestToken(form);
    }

    /**
     * docs-api acting as itself, like the scheduled job.
     */
    private static String docsApiSystemToken()
    {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", "docs-api");
        form.add("client_secret", DOCS_API_SECRET);
        return requestToken(form);
    }

    /**
     * docs-api acting on alice's behalf: her docs-api token exchanged for an audit-service one.
     */
    private static String aliceExchangedToken()
    {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        form.add("client_id", "docs-api");
        form.add("client_secret", DOCS_API_SECRET);
        form.add("subject_token", aliceDocsApiToken());
        form.add("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        form.add("audience", "audit-service");
        return requestToken(form);
    }

    // ---- helpers ----

    private ResultActions postEvent(String token, String body) throws Exception
    {
        return mockMvc.perform(post("/audit-events")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private void assertNothingRecorded()
    {
        assertThat(auditEventRepository.findAll().size()).isZero();
    }

    private static JWTClaimsSet claimsOf(String token) throws Exception
    {
        return SignedJWT.parse(token).getJWTClaimsSet();
    }

    // ---- the attack ----

    @Test
    void replayedDocsApiToken_isRejected() throws Exception
    {
        String stolen = aliceDocsApiToken();

        // Make sure the attack is real: a genuine token, but issued for docs-api, not audit-service
        assertThat(claimsOf(stolen).getAudience())
                .contains("docs-api")
                .doesNotContain("audit-service");

        postEvent(stolen, """
                {"action": "DOCUMENT_UPDATED", "documentId": 1}
                """)
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")));

        assertNothingRecorded();
    }

    // ---- positive controls: the two legitimate paths, with real tokens ----

    @Test
    void systemToken_isAccepted_andRecordsNoActor() throws Exception
    {
        postEvent(docsApiSystemToken(), """
                {"action": "SYSTEM_SNAPSHOT"}
                """).andExpect(status().isCreated());

        AuditEvent event = auditEventRepository.findAll().get(0);
        assertThat(event.getActorUserId()).isNull();
        assertThat(event.getCallerKind()).isEqualTo(CallerKind.SYSTEM);
        assertThat(event.getViaClient()).isEqualTo("docs-api");
    }

    @Test
    void exchangedToken_isAccepted_andRecordsAlice() throws Exception
    {
        String exchanged = aliceExchangedToken();

        JWTClaimsSet claims = claimsOf(exchanged);
        assertThat(claims.getAudience()).contains("audit-service");
        assertThat(claims.getSubject()).isEqualTo(ALICE);

        postEvent(exchanged, """
                {"action": "DOCUMENT_UPDATED", "documentId": 1}
                """).andExpect(status().isCreated());

        AuditEvent event = auditEventRepository.findAll().get(0);
        assertThat(event.getActorUserId()).isEqualTo(ALICE);
        assertThat(event.getDocumentId()).isEqualTo(1L);
        assertThat(event.getCallerKind()).isEqualTo(CallerKind.USER);
        assertThat(event.getViaClient()).isEqualTo("docs-api");
    }
}