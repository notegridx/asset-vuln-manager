package dev.notegridx.security.assetvulnmanager.infra.nvd;

import java.util.Optional;

import org.springframework.stereotype.Component;

/**
 * Minimal CPE 2.3 URI parser for extracting vendor/product from criteria.
 * Example: cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*
 */
@Component
public class CpeNameParser {

    public Optional<VendorProduct> parseVendorProduct(String cpe23Uri) {
        if (cpe23Uri == null) return Optional.empty();
        String s = cpe23Uri.trim();
        if (s.isEmpty()) return Optional.empty();
        if (!s.startsWith("cpe:2.3:")) return Optional.empty();

        // CPE 2.3: cpe:2.3:<part>:<vendor>:<product>:<version>:...
        String[] parts = s.split(":", -1);
        // indices: 0=cpe,1=2.3,2=part,3=vendor,4=product
        if (parts.length < 5) return Optional.empty();

        String vendor = unescape(parts[3]);
        String product = unescape(parts[4]);

        vendor = normalizeNullable(vendor);
        product = normalizeNullable(product);

        if (vendor == null || product == null) return Optional.empty();
        return Optional.of(new VendorProduct(vendor, product));
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        return t;
    }

    /**
     * Very small unescape for CPE 2.3.
     * CPE uses backslash escapes for some characters.
     * For our purpose (vendor/product keying), we minimally handle "\:" and "\\"
     */
    private static String unescape(String s) {
        if (s == null || s.indexOf('\\') < 0) return s;

        StringBuilder sb = new StringBuilder(s.length());
        boolean esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) {
                // keep the escaped char as-is (":", "\", etc.)
                sb.append(c);
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else {
                sb.append(c);
            }
        }
        if (esc) sb.append('\\'); // trailing backslash, keep it
        return sb.toString();
    }

    public record VendorProduct(String vendor, String product) {}
}