package utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.HexFormat;

public class ApiKeys
{
    private static final String PREFIX = "dk";
    private static final HexFormat HEX = HexFormat.of();

    private ApiKeys() {}

    public record ParsedApiKey(String keyId, String secret)
    {
        @Override
        public String toString()
        {
            return "ParsedApiKey[keyId=" + keyId + ", secret=****]";
        }
    }

    public static Optional<ParsedApiKey> parse(String rawKey)
    {
        if(rawKey == null) return Optional.empty();

        String[] parts = rawKey.split("_", 3);
        if(parts.length != 3 || !PREFIX.equals(parts[0]) || parts[1].isBlank() || parts[2].isBlank()) return Optional.empty();

        return Optional.of(new ParsedApiKey(parts[1], parts[2]));
    }

    public static String hash(String secret)
    {
        return HEX.formatHex(sha256(secret));
    }

    public static boolean matches(String secret, String storedHash)
    {
        byte[] stored;
        try
        {
            stored = HEX.parseHex(storedHash);
        }
        catch(IllegalArgumentException e)
        {
            return false;
        }
        return MessageDigest.isEqual(sha256(secret), stored);
    }

    private static byte[] sha256(String input)
    {
        try
        {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        }
        catch(NoSuchAlgorithmException e)
        {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
