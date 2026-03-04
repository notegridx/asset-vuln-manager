package dev.notegridx.security.assetvulnmanager.service;

import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class VendorProductNormalizer {

    // ------------------------------------------------------------
    // Patterns
    // ------------------------------------------------------------

    // DN parsing (publisher_raw)
    private static final Pattern DN_O = Pattern.compile("(?i)(?:^|,)\\s*O\\s*=\\s*([^,]+)");
    private static final Pattern DN_CN = Pattern.compile("(?i)(?:^|,)\\s*CN\\s*=\\s*([^,]+)");

    // vendor legal suffix
    private static final Pattern VENDOR_SUFFIX = Pattern.compile(
            "(?i)\\b(inc|inc\\.|llc|ltd|ltd\\.|corp|corp\\.|corporation|company|co\\.|gmbh|s\\.a\\.|ag|technologies|technology|foundation)\\b"
    );

    // common vendor phrases
    private static final Pattern VENDOR_PHRASE = Pattern.compile("(?i)and/or its affiliates");

    // product noise
    private static final Pattern PRODUCT_PAREN = Pattern.compile(
            "(?i)\\((x64|x86|64-bit|32-bit|amd64|arm64|arm|user|system|dv|sson|usb|per-user|per machine|machine)\\)"
    );

    private static final Pattern PRODUCT_LOCALE = Pattern.compile("(?i)\\b[a-z]{2}-[a-z]{2}\\b");

    private static final Pattern PRODUCT_VERSION_SUFFIX = Pattern.compile(
            "(?i)\\s+v?\\d+(?:\\.\\d+){1,4}.*$"
    );

    private static final Pattern PRODUCT_JAVA_UPDATE = Pattern.compile("(?i)\\s+update\\s+\\d+.*$");

    // ------------------------------------------------------------
    // Vendor
    // ------------------------------------------------------------

    public String normalizeVendor(String s) {
        if (s == null) return null;

        String x = s.trim();
        if (x.isEmpty()) return null;

        // DN extraction
        String dn = extractDnOrganization(x);
        if (dn != null) {
            x = dn;
        }

        // remove phrases
        x = VENDOR_PHRASE.matcher(x).replaceAll(" ");

        // remove legal suffix
        x = VENDOR_SUFFIX.matcher(x).replaceAll(" ");

        x = x.replaceAll("\\s+", " ").trim();

        return normalizeKey(x);
    }

    // ------------------------------------------------------------
    // Product
    // ------------------------------------------------------------

    public String normalizeProduct(String s) {
        if (s == null) return null;

        String x = s.trim();
        if (x.isEmpty()) return null;

        // remove parentheses noise
        x = PRODUCT_PAREN.matcher(x).replaceAll(" ");

        // remove locale
        x = PRODUCT_LOCALE.matcher(x).replaceAll(" ");

        // remove java update
        x = PRODUCT_JAVA_UPDATE.matcher(x).replaceAll("");

        // remove trailing version
        x = PRODUCT_VERSION_SUFFIX.matcher(x).replaceAll("");

        x = x.replaceAll("\\s+", " ").trim();

        return normalizeKey(x);
    }

    // ------------------------------------------------------------
    // DN extraction
    // ------------------------------------------------------------

    private String extractDnOrganization(String s) {

        if (!s.contains("=")) return null;

        Matcher m = DN_O.matcher(s);
        if (m.find()) {
            return m.group(1).trim();
        }

        Matcher m2 = DN_CN.matcher(s);
        if (m2.find()) {
            return m2.group(1).trim();
        }

        return null;
    }

    // ------------------------------------------------------------
    // Base normalize
    // ------------------------------------------------------------

    public String normalizeKey(String s) {

        if (s == null) return null;

        String t = s.trim();
        if (t.isEmpty()) return null;

        String x = Normalizer.normalize(t, Normalizer.Form.NFKC);
        x = x.toLowerCase(Locale.ROOT);

        x = x.replaceAll("\\s+", " ").trim();
        x = x.replaceAll("[^a-z0-9 ._\\-+]", "");
        x = x.replaceAll("\\s+", " ").trim();

        return x.isEmpty() ? null : x;
    }
}