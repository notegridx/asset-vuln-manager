package dev.notegridx.security.assetvulnmanager.service.seed;

import java.util.ArrayList;
import java.util.List;

public class AliasSeedPayload {

    private int version = 1;
    private String source;

    private List<VendorSeed> vendors = new ArrayList<>();
    private List<ProductSeed> products = new ArrayList<>();

    public int getVersion() { return version; }
    public void setVersion(int version) { this.version = version; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public List<VendorSeed> getVendors() { return vendors; }
    public void setVendors(List<VendorSeed> vendors) { this.vendors = vendors; }

    public List<ProductSeed> getProducts() { return products; }
    public void setProducts(List<ProductSeed> products) { this.products = products; }

    // -------- nested --------

    public static class VendorSeed {
        private String canonicalVendor; // cpe_vendors.name_norm
        private List<AliasItem> aliases = new ArrayList<>();

        public String getCanonicalVendor() { return canonicalVendor; }
        public void setCanonicalVendor(String canonicalVendor) { this.canonicalVendor = canonicalVendor; }

        public List<AliasItem> getAliases() { return aliases; }
        public void setAliases(List<AliasItem> aliases) { this.aliases = aliases; }
    }

    public static class ProductSeed {
        private String canonicalVendor;  // cpe_vendors.name_norm
        private String canonicalProduct; // cpe_products.name_norm (scoped by vendor)
        private List<AliasItem> aliases = new ArrayList<>();

        public String getCanonicalVendor() { return canonicalVendor; }
        public void setCanonicalVendor(String canonicalVendor) { this.canonicalVendor = canonicalVendor; }

        public String getCanonicalProduct() { return canonicalProduct; }
        public void setCanonicalProduct(String canonicalProduct) { this.canonicalProduct = canonicalProduct; }

        public List<AliasItem> getAliases() { return aliases; }
        public void setAliases(List<AliasItem> aliases) { this.aliases = aliases; }
    }

    public static class AliasItem {
        private String raw;
        private Integer confidence;   // 0..100 (recommended)
        private String evidenceUrl;   // optional

        public String getRaw() { return raw; }
        public void setRaw(String raw) { this.raw = raw; }

        public Integer getConfidence() { return confidence; }
        public void setConfidence(Integer confidence) { this.confidence = confidence; }

        public String getEvidenceUrl() { return evidenceUrl; }
        public void setEvidenceUrl(String evidenceUrl) { this.evidenceUrl = evidenceUrl; }
    }
}