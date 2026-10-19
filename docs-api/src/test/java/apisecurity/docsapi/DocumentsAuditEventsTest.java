package apisecurity.docsapi;

import apisecurity.docsapi.enums.AuditAction;
import apisecurity.docsapi.events.DocumentChangedEvent;
import apisecurity.docsapi.repositories.DocumentRepository;
import org.springframework.transaction.annotation.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.event.ApplicationEvents;
import org.springframework.test.context.event.RecordApplicationEvents;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@RecordApplicationEvents
class DocumentAuditEventsTest
{

    static final String ALICE = "11111111-1111-1111-1111-111111111111";
    static final String BOB = "22222222-2222-2222-2222-222222222222";

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ApplicationEvents applicationEvents;
    @Autowired
    DocumentRepository documentRepository;

    Long alicePrivateId;

    @BeforeEach
    void findSeededIds()
    {
        alicePrivateId = documentRepository.findAllForAdmin().stream()
                .filter(d -> d.getTitle().equals("Alice's private notes"))
                .findFirst().orElseThrow().getId();
    }

    private static RequestPostProcessor user(String sub)
    {
        return jwt().jwt(j -> j.subject(sub)).authorities(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Test
    void successfulUpdate_publishesAuditEvent() throws Exception
    {
        mockMvc.perform(put("/documents/{id}", alicePrivateId).with(user(ALICE))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title": "new", "content": "new"}
                                """))
                .andExpect(status().is2xxSuccessful());

        assertThat(applicationEvents.stream(DocumentChangedEvent.class))
                .containsExactly(new DocumentChangedEvent(AuditAction.DOCUMENT_UPDATED, alicePrivateId));
    }

    @Test
    void rejectedUpdate_publishesNothing() throws Exception
    {
        mockMvc.perform(put("/documents/{id}", alicePrivateId).with(user(BOB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title": "pwned", "content": "pwned"}
                                """))
                .andExpect(status().isNotFound());

        assertThat(applicationEvents.stream(DocumentChangedEvent.class)).isEmpty();
    }
}