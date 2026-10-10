package apisecurity.docsapi.authorization;

import apisecurity.docsapi.entities.Document;
import apisecurity.docsapi.repositories.DocumentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class DocumentAuthorizationTest
{

    static final String ALICE = "11111111-1111-1111-1111-111111111111";
    static final String BOB   = "22222222-2222-2222-2222-222222222222";
    static final String CAROL = "33333333-3333-3333-3333-333333333333";

    @Autowired MockMvc mockMvc;
    @Autowired DocumentRepository documentRepository;

    Long alicePrivateId;
    Long aliceSharedId;
    Long bobPrivateId;

    @BeforeEach
    void findSeededIds()
    {
        Map<String, Long> idsByTitle = documentRepository.findAllForAdmin().stream()
                .collect(Collectors.toMap(Document::getTitle, Document::getId));
        alicePrivateId = idsByTitle.get("Alice's private notes");
        aliceSharedId  = idsByTitle.get("Alice's shared notes with Bob");
        bobPrivateId   = idsByTitle.get("Bob's private notes");
    }

    // ---- fake users ----

    private static RequestPostProcessor user(String sub)
    {
        return jwt().jwt(j -> j.subject(sub))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"));
    }

    private static RequestPostProcessor admin(String sub)
    {
        return jwt().jwt(j -> j.subject(sub))
                .authorities(new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    // ---- authentication ----

    @Test
    void noToken_isRejectedWith401() throws Exception
    {
        mockMvc.perform(get("/documents"))
                .andExpect(status().isUnauthorized());
    }

    // ---- BOLA: reading ----

    @Test
    void bob_cannotReadAlicesPrivateDoc_andLearnsNothingAboutIt() throws Exception
    {
        mockMvc.perform(get("/documents/{id}", alicePrivateId).with(user(BOB)))
                .andExpect(status().isNotFound());
    }

    @Test
    void bob_canReadDocSharedWithHim() throws Exception
    {
        mockMvc.perform(get("/documents/{id}", aliceSharedId).with(user(BOB)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ownerId").value(ALICE));
    }

    @Test
    void list_containsOnlyDocsVisibleToCaller() throws Exception
    {
        mockMvc.perform(get("/documents").with(user(ALICE)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].ownerId", everyItem(is(ALICE))));

        mockMvc.perform(get("/documents").with(user(BOB)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(2)))
                .andExpect(jsonPath("$[*].documentId",
                        not(hasItem(alicePrivateId.intValue()))));
    }

    // ---- BOLA: writing ----

    @Test
    void bob_cannotUpdateAlicesPrivateDoc() throws Exception
    {
        mockMvc.perform(put("/documents/{id}", alicePrivateId).with(user(BOB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title": "pwned", "content": "pwned"}
                                """))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/documents/{id}", alicePrivateId).with(user(ALICE)))
                .andExpect(jsonPath("$.title").value(not("pwned")));
    }

    @Test
    void bob_canEditDocSharedWithHim() throws Exception
    {
        mockMvc.perform(put("/documents/{id}", aliceSharedId).with(user(BOB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title": "edited by bob", "content": "new content"}
                                """))
                .andExpect(status().is2xxSuccessful());

        mockMvc.perform(get("/documents/{id}", aliceSharedId).with(user(ALICE)))
                .andExpect(jsonPath("$.title").value("edited by bob"));
    }

    @Test
    void bob_cannotDeleteDocSharedWithHim() throws Exception
    {
        mockMvc.perform(delete("/documents/{id}", aliceSharedId).with(user(BOB)))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/documents/{id}", aliceSharedId).with(user(ALICE)))
                .andExpect(status().isOk());
    }

    @Test
    void bob_cannotReshareDocSharedWithHim() throws Exception
    {
        mockMvc.perform(post("/documents/{id}/shares", aliceSharedId).with(user(BOB))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"userIds": ["%s"]}
                                """.formatted(CAROL)))
                .andExpect(status().isForbidden());
    }

    @Test
    void owner_canDeleteOwnDoc() throws Exception
    {
        mockMvc.perform(delete("/documents/{id}", alicePrivateId).with(user(ALICE)))
                .andExpect(status().is2xxSuccessful());

        mockMvc.perform(get("/documents/{id}", alicePrivateId).with(user(ALICE)))
                .andExpect(status().isNotFound());
    }

    // ---- mass assignment ----

    @Test
    void create_ignoresOwnerIdInBody() throws Exception
    {
        mockMvc.perform(post("/documents").with(user(ALICE))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title": "mine", "content": "x", "ownerId": "%s"}
                                """.formatted(BOB)))
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.ownerId").value(ALICE));
    }

    // ---- BFLA ----

    @Test
    void regularUser_cannotReachAdminEndpoint() throws Exception
    {
        mockMvc.perform(get("/admin/documents").with(user(ALICE)))
                .andExpect(status().isForbidden());
    }

    @Test
    void admin_canReachAdminEndpoint() throws Exception
    {
        mockMvc.perform(get("/admin/documents").with(admin(CAROL)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(3)));
    }

    @Test
    void internalPaths_areDeniedEvenToAdmins() throws Exception
    {
        mockMvc.perform(get("/internal/anything").with(admin(CAROL)))
                .andExpect(status().isForbidden());
    }

    // ---- input validation ----

    @Test
    void create_withBlankTitle_isRejected() throws Exception
    {
        mockMvc.perform(post("/documents").with(user(ALICE))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"title": "  ", "content": "x"}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void share_withNullUserIds_isRejected() throws Exception
    {
        mockMvc.perform(post("/documents/{id}/shares", alicePrivateId).with(user(ALICE))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }
}
