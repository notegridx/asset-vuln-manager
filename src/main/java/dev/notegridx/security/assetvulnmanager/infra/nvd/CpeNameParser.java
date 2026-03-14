package dev.notegridx.security.assetvulnmanager.infra.nvd;

import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * CPE 2.3 URI parser.
 *
 * Example:
 * cpe:2.3:a:microsoft:edge:*:*:*:*:*:windows:*:*
 *
 * indices:
 * 0=cpe
 * 1=2.3
 * 2=part
 * 3=vendor
 * 4=product
 * 5=version
 * 6=update
 * 7=edition
 * 8=language
 * 9=sw_edition
 * 10=target_sw
 * 11=target_hw
 * 12=other
 */
@Component
public class CpeNameParser {

    public Optional<VendorProduct> parseVendorProduct(String cpe23Uri) {
        return parse(cpe23Uri).map(p -> new VendorProduct(p.vendor(), p.product()));
    }

    public Optional<ParsedCpe23> parse(String cpe23Uri) {
        if (cpe23Uri == null) return Optional.empty();

        String s = cpe23Uri.trim();
        if (s.isEmpty()) return Optional.empty();
        if (!s.startsWith("cpe:2.3:")) return Optional.empty();

        String[] parts = s.split(":", -1);
        if (parts.length < 13) return Optional.empty();

        String part = normalizeNullable(unescape(parts[2]));
        String vendor = normalizeNullable(unescape(parts[3]));
        String product = normalizeNullable(unescape(parts[4]));
        String version = normalizeNullable(unescape(parts[5]));
        String targetSw = normalizeNullable(unescape(parts[10]));
        String targetHw = normalizeNullable(unescape(parts[11]));

        if (part == null || vendor == null || product == null) {
            return Optional.empty();
        }

        return Optional.of(new ParsedCpe23(
                part,
                vendor,
                product,
                version,
                targetSw,
                targetHw
        ));
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * Minimal CPE 2.3 unescape.
     */
    private static String unescape(String s) {
        if (s == null || s.indexOf('\\') < 0) return s;

        StringBuilder sb = new StringBuilder(s.length());
        boolean esc = false;

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (esc) {
                sb.append(c);
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else {
                sb.append(c);
            }
        }

        if (esc) {
            sb.append('\\');
        }

        return sb.toString();
    }

    public record VendorProduct(String vendor, String product) {
    }

    public record ParsedCpe23(
            String part,
            String vendor,
            String product,
            String version,
            String targetSw,
            String targetHw
    ) {
    }
}