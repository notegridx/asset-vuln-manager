package dev.notegridx.security.assetvulnmanager.infra.nvd;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Parses NVD feed .meta files (text).
 *
 * Example lines (may vary):
 * lastModifiedDate: 2026-02-19Txx:xx:xx-xx:xx
 * size: 123456789
 * sha256: ...
 */
public class CveFeedMetaParser {

    public FeedMeta parse(InputStream in) throws IOException {
        String lastModified = null;
        Long size = null;
        String sha256 = null;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                String t = line.trim();
                if (t.isEmpty()) continue;

                int idx = t.indexOf(':');
                if (idx < 0) continue;

                String key = t.substring(0, idx).trim();
                String val = t.substring(idx + 1).trim();

                if ("lastModifiedDate".equalsIgnoreCase(key) || "lastModified".equalsIgnoreCase(key)) {
                    lastModified = val;
                } else if ("size".equalsIgnoreCase(key)) {
                    try {
                        size = Long.parseLong(val);
                    } catch (NumberFormatException ignore) {
                        // ignore
                    }
                } else if ("sha256".equalsIgnoreCase(key)) {
                    sha256 = val;
                }
            }
        }

        return new FeedMeta(sha256, lastModified, size);
    }

    public record FeedMeta(String sha256, String lastModified, Long size) {}
}