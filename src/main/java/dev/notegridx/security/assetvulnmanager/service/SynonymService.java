package dev.notegridx.security.assetvulnmanager.service;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SynonymService {

    // 後でDB化して差し替え
    private final Map<String, String> vendorAlias = Map.of(
            "ms", "microsoft",
            "microsoft corporation", "microsoft",
            "google inc", "google"
    );

    private final Map<String, Map<String, String>> productAliasByVendor = Map.of(
            "microsoft", Map.of(
                    "ms edge", "edge",
                    "microsoft edge", "edge"
            )
    );

    public String canonicalVendorOrSame(String vendorNorm) {
        if (vendorNorm == null) return null;
        return vendorAlias.getOrDefault(vendorNorm, vendorNorm);
    }

    public String canonicalProductOrSame(String vendorNorm, String productNorm) {
        if (productNorm == null) return null;
        if (vendorNorm == null) return productNorm;

        Map<String, String> m = productAliasByVendor.get(vendorNorm);
        if (m == null) return productNorm;
        return m.getOrDefault(productNorm, productNorm);
    }
}
