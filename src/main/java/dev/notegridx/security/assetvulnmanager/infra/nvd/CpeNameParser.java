package dev.notegridx.security.assetvulnmanager.infra.nvd;

import java.util.Optional;

public class CpeNameParser {

    public record VendorProduct(String vendor, String product) {}

    public Optional<VendorProduct> parseVendorProduct(String cpe23Uri) {
        if (cpe23Uri == null) return Optional.empty();
        String s = cpe23Uri.trim();
        if (!s.startsWith("cpe:2.3:")) return Optional.empty();

        String[] parts = s.split(":", -1);
        if (parts.length < 5) return Optional.empty();

        String vendor = parts[3];
        String product = parts[4];

        vendor = normalize(vendor);
        product = normalize(product);

        if (vendor == null || product == null) return Optional.empty();
        return Optional.of(new VendorProduct(vendor, product));
    }

    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
