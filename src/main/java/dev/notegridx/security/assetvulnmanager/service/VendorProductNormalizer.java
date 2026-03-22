package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.SystemSetting;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_ARCH_PAREN;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_JAVA_UPDATE_SUFFIX;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_LOCALE_TAG;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_VERSION_SUFFIX;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_VENDOR_EXTRACT_DN_ORGANIZATION;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_COMMON_PHRASES;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_LEGAL_SUFFIX;

@Component
public class VendorProductNormalizer {

    private final SystemSettingRepository systemSettingRepository;

    public VendorProductNormalizer(SystemSettingRepository systemSettingRepository) {
        this.systemSettingRepository = systemSettingRepository;
    }

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
        if (isEnabled(KEY_CANONICAL_NORMALIZE_VENDOR_EXTRACT_DN_ORGANIZATION, true)) {
            String dn = extractDnOrganization(x);
            if (dn != null) {
                x = dn;
            }
        }

        // remove phrases
        if (isEnabled(KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_COMMON_PHRASES, true)) {
            x = VENDOR_PHRASE.matcher(x).replaceAll(" ");
        }

        // remove legal suffix
        if (isEnabled(KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_LEGAL_SUFFIX, true)) {
            x = VENDOR_SUFFIX.matcher(x).replaceAll(" ");
        }

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
        if (isEnabled(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_ARCH_PAREN, true)) {
            x = PRODUCT_PAREN.matcher(x).replaceAll(" ");
        }

        // remove locale
        if (isEnabled(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_LOCALE_TAG, true)) {
            x = PRODUCT_LOCALE.matcher(x).replaceAll(" ");
        }

        // remove java update
        if (isEnabled(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_JAVA_UPDATE_SUFFIX, true)) {
            x = PRODUCT_JAVA_UPDATE.matcher(x).replaceAll("");
        }

        // remove trailing version
        if (isEnabled(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_VERSION_SUFFIX, true)) {
            x = PRODUCT_VERSION_SUFFIX.matcher(x).replaceAll("");
        }

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

    // ------------------------------------------------------------
    // Settings
    // ------------------------------------------------------------

    private boolean isEnabled(String key, boolean defaultValue) {
        return systemSettingRepository.findById(key)
                .map(SystemSetting::getSettingValue)
                .map(v -> "true".equalsIgnoreCase(v))
                .orElse(defaultValue);
    }
}