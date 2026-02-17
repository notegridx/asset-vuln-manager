package dev.notegridx.security.assetvulnmanager.service;

import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Locale;

@Component
public class VendorProductNormalizer {

    public String normalizeVendor(String s) {
        return normalizeKey(s);
    }

    public String normalizeProduct(String s) {
        return normalizeKey(s);
    }

    public String normalizeKey(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;

        String x = Normalizer.normalize(t, Normalizer.Form.NFKC);
        x = x.toLowerCase(Locale.ROOT);

        x = x.replaceAll("\\s+", " ").trim();
        x = x.replaceAll("[^a-z0-9 ._\\-]", "");
        x = x.replaceAll("\\s+", " ").trim();

        return x.isEmpty() ? null : x;
    }
}
