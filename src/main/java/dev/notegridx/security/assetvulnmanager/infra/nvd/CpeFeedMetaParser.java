package dev.notegridx.security.assetvulnmanager.infra.nvd;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;

import java.io.IOException;
import java.io.InputStream;

public class CpeFeedMetaParser {

    public record FeedMeta(String sha256, String lastModified, Long size) {}

    private final JsonFactory jsonFactory = new JsonFactory();

    public FeedMeta parse(InputStream in) throws IOException {

        String sha256 = null;
        String lastModified = null;
        Long size = null;

        try (JsonParser p = jsonFactory.createParser(in)) {
            while (p.nextToken() != null) {

                if (p.currentToken() == JsonToken.FIELD_NAME) {
                    String field = p.currentName();
                    JsonToken v = p.nextToken();

                    if (v == JsonToken.VALUE_STRING) {
                        String val = p.getValueAsString();

                        if (equalsAny(field, "sha256", "SHA256", "hash")) sha256 = val;
                        if (equalsAny(field, "lastModified", "last_modified", "Last-Modified")) lastModified = val;
                        if (equalsAny(field, "size", "fileSize", "metaSize")) {
                            try {
                                size = Long.parseLong(val);
                            } catch (NumberFormatException ignore) {}
                        }
                    }

                    if (v == JsonToken.VALUE_NUMBER_INT) {
                        if (equalsAny(field, "size", "fileSize", "metaSize")) {
                            size = p.getLongValue();
                        }
                    }
                }
            }
        }
        return new FeedMeta(sha256, lastModified, size);
    }

    private static boolean equalsAny(String s, String... cands) {
        if (s == null) return false;
        for (String c : cands) {
            if (c.equalsIgnoreCase(s)) return true;
        }
        return false;
    }

}
