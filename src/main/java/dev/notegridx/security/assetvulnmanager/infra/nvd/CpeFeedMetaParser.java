package dev.notegridx.security.assetvulnmanager.infra.nvd;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class CpeFeedMetaParser {

    /**
     * Metadata extracted from NVD CPE feed meta file.
     *
     * sha256: hash of the feed content (gzip/json/etc.)
     * lastModified: last update timestamp from meta
     * size: feed size (gzipSize / size / fileSize variants)
     */
    public record FeedMeta(String sha256, String lastModified, Long size) {
    }

    private final JsonFactory jsonFactory = new JsonFactory();

    public FeedMeta parse(InputStream in) throws IOException {

        byte[] bytes = in.readAllBytes();
        String text = new String(bytes, StandardCharsets.UTF_8);

        String trimmed = ltrim(text);
        if (!trimmed.isEmpty()) {
            char c = trimmed.charAt(0);
            if (c == '{' || c == '[') {
                FeedMeta m = parseAsJson(bytes);
                if (m != null) return m;
            }
        }

        return parseAsKeyValueText(text);
    }

    private FeedMeta parseAsKeyValueText(String text) {

        String sha256 = null;
        String lastModified = null;
        Long size = null;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8))) {

            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty()) continue;

                int idx = t.indexOf(':');
                int eq = t.indexOf('=');
                if (idx < 0 || (eq >= 0 && eq < idx)) idx = eq;

                if (idx <= 0) continue;

                String key = t.substring(0, idx).trim();
                String val = t.substring(idx + 1).trim();

                val = stripQuotes(val);

                String k = key.toLowerCase(Locale.ROOT);

                if (sha256 == null && (k.contains("sha256") || k.equals("hash"))) {
                    sha256 = emptyToNull(val);
                    continue;
                }

                if (lastModified == null && (k.contains("lastmodified") || k.contains("last-modified") || k.contains("last_modified"))) {
                    lastModified = emptyToNull(val);
                    continue;
                }

                if (size == null && (k.contains("size") || k.contains("filesize"))) {
                    Long parsed = tryParseLong(val);
                    if (parsed != null) size = parsed;
                }
            }
        } catch (IOException ignore) {
        }

        return new FeedMeta(sha256, lastModified, size);
    }

    private FeedMeta parseAsJson(byte[] bytes) {
        String sha256 = null;
        String lastModified = null;
        Long size = null;

        try (JsonParser p = jsonFactory.createParser(bytes)) {
            while (p.nextToken() != null) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (v == JsonToken.VALUE_STRING) {
                    String val = p.getValueAsString();
                    if (equalsAny(field, "sha256", "SHA256", "hash", "gzipSha256", "gzSha256")) sha256 = val;
                    if (equalsAny(field, "lastModified", "lastModifiedDate", "last_modified", "Last-Modified"))
                        lastModified = val;

                    if (equalsAny(field, "size", "fileSize", "metaSize", "gzipSize", "gzSize")) {
                        Long parsed = tryParseLong(val);
                        if (parsed != null) size = parsed;
                    }
                } else if (v == JsonToken.VALUE_NUMBER_INT) {
                    if (equalsAny(field, "size", "fileSize", "metaSize", "gzipSize", "gzSize")) {
                        size = p.getLongValue();
                    }
                }
            }
        } catch (IOException e) {
            return null;
        }

        return new FeedMeta(sha256, lastModified, size);
    }

    private static String ltrim(String s) {
        if (s == null || s.isEmpty()) return "";
        int i = 0;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return s.substring(i);
    }

    private static String stripQuotes(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.length() >= 2) {
            char a = t.charAt(0);
            char b = t.charAt(t.length() - 1);
            if ((a == '"' && b == '"') || (a == '\'' && b == '\'')) {
                return t.substring(1, t.length() - 1).trim();
            }
        }
        return t;
    }

    private static String emptyToNull(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static Long tryParseLong(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;

        // Accept values like "12345" or "12345 bytes" by extracting leading digits only.
        StringBuilder digits = new StringBuilder();
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (Character.isDigit(c)) digits.append(c);
            else break;
        }
        if (digits.isEmpty()) return null;

        try {
            return Long.parseLong(digits.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean equalsAny(String s, String... cands) {
        if (s == null) return false;
        for (String c : cands) {
            if (c.equalsIgnoreCase(s)) return true;
        }
        return false;
    }
}
