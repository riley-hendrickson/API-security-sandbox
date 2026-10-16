package apisecurity.auditservice;

import apisecurity.auditservice.entities.AuditEvent;
import apisecurity.auditservice.enums.Action;
import apisecurity.auditservice.enums.CallerKind;
import apisecurity.auditservice.repositories.AuditEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuditEventSecurityTest
{

    static final String ALICE = "11111111-1111-1111-1111-111111111111";
    static final String SERVICE_ACCOUNT = "bcc084b7-35be-424b-be10-5e59b40dca54";
    static final Instant FIXED_NOW = Instant.parse("2026-01-01T00:00:00Z");

    @TestConfiguration
    static class FixedClockConfig
    {
        @Bean
        @Primary
        Clock fixedClock()
        {
            return Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        }
    }

    @Autowired
    MockMvc mockMvc;
    @Autowired
    AuditEventRepository auditEventRepository;

    // ---- tokens shaped like the real ones from Postman ----

    private static RequestPostProcessor token(Consumer<Jwt.Builder> claims, String... authorities)
    {
        return jwt().jwt(claims)
                .authorities(Arrays.stream(authorities)
                        .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                        .toList());
    }

    /**
     * Exchanged token: alice's session (sid), issued to docs-api, no client_id.
     */
    private static RequestPostProcessor userToken()
    {
        return token(j -> j.subject(ALICE).claim("azp", "docs-api").claim("sid", "session-1"),
                "SCOPE_audit:write");
    }

    /**
     * Client-credentials token: service account, client_id present, no sid.
     */
    private static RequestPostProcessor systemToken()
    {
        return token(j -> j.subject(SERVICE_ACCOUNT).claim("azp", "docs-api").claim("client_id", "docs-api"),
                "SCOPE_audit:write");
    }

    private ResultActions postEvent(RequestPostProcessor token, String body) throws Exception
    {
        return mockMvc.perform(post("/audit-events")
                .with(token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body));
    }

    private void assertNothingRecorded()
    {
        assertThat(auditEventRepository.findAll()).isEmpty();
    }

    // ---- the two legitimate paths ----

    @Test
    void userEvent_recordsActorFromTheToken() throws Exception
    {
        postEvent(userToken(), """
                {"action": "DOCUMENT_UPDATED", "documentId": 7}
                """).andExpect(status().isCreated());

        List<AuditEvent> events = auditEventRepository.findAll();
        assertThat(events).hasSize(1);
        AuditEvent event = events.get(0);
        assertThat(event.getAction()).isEqualTo(Action.DOCUMENT_UPDATED);
        assertThat(event.getDocumentId()).isEqualTo(7L);
        assertThat(event.getActorUserId()).isEqualTo(ALICE);
        assertThat(event.getViaClient()).isEqualTo("docs-api");
        assertThat(event.getCallerKind()).isEqualTo(CallerKind.USER);
        assertThat(event.getOccurredAt()).isEqualTo(FIXED_NOW);
    }

    @Test
    void systemEvent_recordsNoActor() throws Exception
    {
        postEvent(systemToken(), """
                {"action": "SYSTEM_SNAPSHOT"}
                """).andExpect(status().isCreated());

        AuditEvent event = auditEventRepository.findAll().get(0);
        assertThat(event.getActorUserId()).isNull();
        assertThat(event.getDocumentId()).isNull();
        assertThat(event.getCallerKind()).isEqualTo(CallerKind.SYSTEM);
        assertThat(event.getViaClient()).isEqualTo("docs-api");
    }

    // ---- who may call at all ----

    @Test
    void noToken_isRejected() throws Exception
    {
        mockMvc.perform(post("/audit-events")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"action": "SYSTEM_SNAPSHOT"}
                                """))
                .andExpect(status().isUnauthorized());
        assertNothingRecorded();
    }

    @Test
    void callerOtherThanDocsApi_isRejected() throws Exception
    {
        postEvent(token(j -> j.subject(ALICE).claim("azp", "bff").claim("sid", "session-1"),
                "SCOPE_audit:write"), """
                {"action": "DOCUMENT_UPDATED", "documentId": 7}
                """).andExpect(status().isForbidden());
        assertNothingRecorded();
    }

    @Test
    void tokenWithoutAuditScope_isRejected() throws Exception
    {
        postEvent(token(j -> j.subject(ALICE).claim("azp", "docs-api").claim("sid", "session-1"),
                "SCOPE_profile"), """
                {"action": "DOCUMENT_UPDATED", "documentId": 7}
                """).andExpect(status().isForbidden());
        assertNothingRecorded();
    }

    // ---- the actor can't be forged ----

    @Test
    void bodyClaimingAnActor_isRejected() throws Exception
    {
        postEvent(userToken(), """
                {"action": "DOCUMENT_UPDATED", "documentId": 7, "actorUserId": "22222222-2222-2222-2222-222222222222"}
                """).andExpect(status().isBadRequest());
        assertNothingRecorded();
    }

    // ---- caller kind must match the action ----

    @Test
    void userToken_cannotRecordSystemEvents() throws Exception
    {
        postEvent(userToken(), """
                {"action": "SYSTEM_SNAPSHOT"}
                """).andExpect(status().isForbidden());
        assertNothingRecorded();
    }

    @Test
    void systemToken_cannotRecordUserEvents() throws Exception
    {
        postEvent(systemToken(), """
                {"action": "DOCUMENT_DELETED", "documentId": 7}
                """).andExpect(status().isForbidden());
        assertNothingRecorded();
    }

    @Test
    void ambiguousToken_withBothMarkers_isRejected() throws Exception
    {
        postEvent(token(j -> j.subject(ALICE).claim("azp", "docs-api")
                        .claim("sid", "session-1").claim("client_id", "docs-api"),
                "SCOPE_audit:write"), """
                {"action": "DOCUMENT_UPDATED", "documentId": 7}
                """).andExpect(status().isForbidden());
        assertNothingRecorded();
    }

    @Test
    void ambiguousToken_withNeitherMarker_isRejected() throws Exception
    {
        postEvent(token(j -> j.subject(ALICE).claim("azp", "docs-api"),
                "SCOPE_audit:write"), """
                {"action": "DOCUMENT_UPDATED", "documentId": 7}
                """).andExpect(status().isForbidden());
        assertNothingRecorded();
    }

    // ---- body shape ----

    @Test
    void userEvent_withoutDocumentId_isRejected() throws Exception
    {
        postEvent(userToken(), """
                {"action": "DOCUMENT_UPDATED"}
                """).andExpect(status().isBadRequest());
        assertNothingRecorded();
    }

    @Test
    void systemEvent_withDocumentId_isRejected() throws Exception
    {
        postEvent(systemToken(), """
                {"action": "SYSTEM_SNAPSHOT", "documentId": 7}
                """).andExpect(status().isBadRequest());
        assertNothingRecorded();
    }

    @Test
    void unknownAction_isRejected() throws Exception
    {
        postEvent(systemToken(), """
                {"action": "NOT_A_REAL_ACTION"}
                """).andExpect(status().isBadRequest());
        assertNothingRecorded();
    }

    @Test
    void missingAction_isRejected() throws Exception
    {
        postEvent(systemToken(), "{}").andExpect(status().isBadRequest());
        assertNothingRecorded();
    }

    // ---- append-only: nothing but POST exists ----

    @Test
    void readingEvents_isDenied() throws Exception
    {
        mockMvc.perform(get("/audit-events").with(userToken()))
                .andExpect(status().isForbidden());
    }

    @Test
    void deletingEvents_isDenied() throws Exception
    {
        mockMvc.perform(delete("/audit-events/1").with(systemToken()))
                .andExpect(status().isForbidden());
    }
}