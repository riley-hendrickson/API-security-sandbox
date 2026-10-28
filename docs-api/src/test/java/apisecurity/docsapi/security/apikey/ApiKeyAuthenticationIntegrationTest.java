package apisecurity.docsapi.security.apikey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import utils.ApiKeys;

import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiKeyAuthenticationIntegrationTest
{
    private static final String API_KEY_HEADER = "X-API-Key";
    private static final String SUMMARY = "/internal/reports/summary";
    private static final String WRONG_SECRET = "0".repeat(64);

    @Autowired
    MockMvc mockMvc;

    @Value("${apikeys.dev.active}")
    String activeKey;

    @Value("${apikeys.dev.revoked}")
    String revokedKey;

    @Value("${apikeys.dev.expired}")
    String expiredKey;

    // ---------------------------------------------------------------------
    // Happy path
    // ---------------------------------------------------------------------

    @Test
    void activeKey_isAccepted_andIdentifiesTheClient() throws Exception
    {
        mockMvc.perform(get(SUMMARY).header(API_KEY_HEADER, activeKey))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("reporting-tool")));
    }

    // ---------------------------------------------------------------------
    // Every bad key gets the exact same response
    // ---------------------------------------------------------------------

    Stream<Arguments> rejectedKeys()
    {
        String activeKeyId = ApiKeys.parse(activeKey).orElseThrow().keyId();

        return Stream.of(
                Arguments.of("revoked key", revokedKey),
                Arguments.of("expired key", expiredKey),
                Arguments.of("right keyId, wrong secret", "dk_" + activeKeyId + "_" + WRONG_SECRET),
                Arguments.of("unknown keyId", "dk_doesnotexist_" + WRONG_SECRET),
                Arguments.of("missing keyId", "dk__" + WRONG_SECRET),
                Arguments.of("not an API key at all", "not-an-api-key")
        );
    }

    @ParameterizedTest(name = "{0} -> 401")
    @MethodSource("rejectedKeys")
    void badKeys_allGetTheSameEmpty401(String description, String key) throws Exception
    {
        mockMvc.perform(get(SUMMARY).header(API_KEY_HEADER, key))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(""))
                .andExpect(header().doesNotExist("WWW-Authenticate"));
    }

    // ---------------------------------------------------------------------
    // No key at all: pass-through, anonymous, denied by authorization
    // ---------------------------------------------------------------------

    @Test
    void missingHeader_gets401_not403() throws Exception
    {
        mockMvc.perform(get(SUMMARY))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(""));
    }

    @Test
    void blankHeader_isTreatedAsMissing() throws Exception
    {
        mockMvc.perform(get(SUMMARY).header(API_KEY_HEADER, "   "))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(""));
    }

    // ---------------------------------------------------------------------
    // Chain isolation: each chain only understands its own mechanism
    // ---------------------------------------------------------------------

    @Test
    void bearerTokenOnInternalPath_isIgnoredByTheApiKeyChain() throws Exception
    {
        mockMvc.perform(get(SUMMARY).header("Authorization", "Bearer some.jwt.value"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("WWW-Authenticate"));
    }

    @Test
    void apiKeyOnDocumentsEndpoint_isIgnoredByTheJwtChain() throws Exception
    {
        mockMvc.perform(get("/documents").header(API_KEY_HEADER, activeKey))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", startsWith("Bearer")));
    }

    // ---------------------------------------------------------------------
    // Default deny inside /internal/**
    // ---------------------------------------------------------------------

    @Test
    void validKeyOnUnlistedInternalPath_isForbidden() throws Exception
    {
        mockMvc.perform(get("/internal/admin/anything").header(API_KEY_HEADER, activeKey))
                .andExpect(status().isForbidden());
    }
}