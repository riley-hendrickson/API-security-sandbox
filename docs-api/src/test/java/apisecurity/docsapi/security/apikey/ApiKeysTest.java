package apisecurity.docsapi.security.apikey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import utils.ApiKeys;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeysTest
{
    // Standard SHA-256 test vector for "abc" (FIPS 180-2)
    private static final String SHA256_OF_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    @Test
    void hash_matchesTheStandardSha256TestVector()
    {
        assertThat(ApiKeys.hash("abc")).isEqualTo(SHA256_OF_ABC);
    }

    @Test
    void matches_acceptsTheRightSecret_andRejectsAWrongOne()
    {
        String stored = ApiKeys.hash("correct-secret");

        assertThat(ApiKeys.matches("correct-secret", stored)).isTrue();
        assertThat(ApiKeys.matches("wrong-secret", stored)).isFalse();
    }

    @Test
    void matches_returnsFalse_forACorruptStoredHash()
    {
        assertThat(ApiKeys.matches("anything", "not-hex")).isFalse();
    }

    @Test
    void parse_splitsAWellFormedKey()
    {
        ApiKeys.ParsedApiKey parsed = ApiKeys.parse("dk_active01_abc123").orElseThrow();

        assertThat(parsed.keyId()).isEqualTo("active01");
        assertThat(parsed.secret()).isEqualTo("abc123");
    }

    @Test
    void parse_keepsUnderscoresInsideTheSecret()
    {
        ApiKeys.ParsedApiKey parsed = ApiKeys.parse("dk_active01_ab_cd_ef").orElseThrow();

        assertThat(parsed.secret()).isEqualTo("ab_cd_ef");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {
            "",
            "dk",
            "dk_active01",
            "dk__secret",
            "dk_active01_",
            "xx_active01_secret",
            "Bearer eyJhbGciOiJSUzI1NiJ9.e30.sig"
    })
    void parse_rejectsMalformedInput(String rawKey)
    {
        assertThat(ApiKeys.parse(rawKey)).isEmpty();
    }

    @Test
    void parsedKey_toString_hidesTheSecret()
    {
        ApiKeys.ParsedApiKey parsed = ApiKeys.parse("dk_active01_topsecret").orElseThrow();

        assertThat(parsed.toString()).contains("active01").doesNotContain("topsecret");
    }
}