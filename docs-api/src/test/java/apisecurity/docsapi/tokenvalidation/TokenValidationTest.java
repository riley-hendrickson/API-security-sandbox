package apisecurity.docsapi.tokenvalidation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TokenValidationTest extends KeycloakIntegrationTest
{

    @Autowired MockMvc mockMvc;

    // ---- helpers ----

    private ResultActions callApiWith(String token) throws Exception
    {
        return mockMvc.perform(get("/documents")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token));
    }

    private static ResultMatcher rejectedAsInvalidToken()
    {
        return result ->
        {
            status().isUnauthorized().match(result);
            header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("invalid_token")).match(result);
        };
    }

    private static String b64url(String json)
    {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String decodeSegment(String segment)
    {
        return new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
    }

    // ---- positive control ----

    @Test
    void realToken_isAccepted() throws Exception
    {
        callApiWith(aliceToken()).andExpect(status().isOk());
    }

    // ---- forged tokens ----

    @Test
    void tamperedPayload_isRejected() throws Exception
    {
        String[] parts = aliceToken().split("\\.");
        String payload = decodeSegment(parts[1]);
        assertThat(payload).contains(ALICE); // make sure the forgery actually changes something

        String forgedPayload = payload.replace(ALICE, BOB);
        String tampered = parts[0] + "." + b64url(forgedPayload) + "." + parts[2];

        callApiWith(tampered).andExpect(rejectedAsInvalidToken());
    }

    @Test
    void algNone_isRejected() throws Exception
    {
        String[] parts = aliceToken().split("\\.");
        String unsigned = b64url("{\"alg\":\"none\",\"typ\":\"JWT\"}") + "." + parts[1] + ".";

        callApiWith(unsigned).andExpect(rejectedAsInvalidToken());
    }

    @Test
    void signedWithAttackersKey_isRejected() throws Exception
    {
        SignedJWT real = SignedJWT.parse(aliceToken());

        // Same kid as Keycloak's real key, so the decoder picks that key and the signature check fails
        RSAKey attackerKey = new RSAKeyGenerator(2048)
                .keyID(real.getHeader().getKeyID())
                .generate();

        SignedJWT forged = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(attackerKey.getKeyID())
                        .type(JOSEObjectType.JWT)
                        .build(),
                real.getJWTClaimsSet());
        forged.sign(new RSASSASigner(attackerKey));

        callApiWith(forged.serialize()).andExpect(rejectedAsInvalidToken());
    }

    // ---- genuine tokens that still shouldn't get in ----

    @Test
    void tokenForAnotherAudience_isRejected() throws Exception
    {
        String token = tokenFor("other-client", OTHER_CLIENT_SECRET, "alice", "alice");
        assertThat(SignedJWT.parse(token).getJWTClaimsSet().getAudience())
                .doesNotContain("docs-api"); // make sure the test tests what it claims

        callApiWith(token).andExpect(rejectedAsInvalidToken());
    }
}