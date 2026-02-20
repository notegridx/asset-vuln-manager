package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import dev.notegridx.security.assetvulnmanager.service.VendorProductNormalizer;

@RestController
public class DictionarySuggestController {

    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;

    public DictionarySuggestController(
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            VendorProductNormalizer normalizer,
            SynonymService synonymService
    ) {
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.normalizer = normalizer;
        this.synonymService = synonymService;
    }

    public record SuggestItem(String value, String label) {}

    /**
     * Vendor候補（name_norm 前方一致）
     * Example: GET /api/dict/vendors?q=mic
     */
    @GetMapping("/api/dict/vendors")
    public List<SuggestItem> suggestVendors(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        String v0 = normalizer.normalizeVendor(q);
        if (v0 == null || v0.isBlank() || v0.length() < 2) return List.of();

        String v1 = synonymService.canonicalVendorOrSame(v0);
        if (v1 == null || v1.isBlank() || v1.length() < 2) return List.of();

        List<CpeVendor> rows = vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc(v1);

        return rows.stream()
                .map(v -> new SuggestItem(
                        v.getNameNorm(),
                        (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName()
                ))
                .toList();
    }

    /**
     * Product候補（vendor確定 → vendor配下の product を name_norm 前方一致）
     * Example: GET /api/dict/products?vendor=microsoft&q=ed
     */
    @GetMapping("/api/dict/products")
    public List<SuggestItem> suggestProducts(
            @RequestParam(name = "vendor", defaultValue = "") String vendorRaw,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        String v0 = normalizer.normalizeVendor(vendorRaw);
        if (v0 == null || v0.isBlank()) return List.of();

        String v1 = synonymService.canonicalVendorOrSame(v0);
        if (v1 == null || v1.isBlank()) return List.of();

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) return List.of();

        String p0 = normalizer.normalizeProduct(q);
        if (p0 == null || p0.isBlank() || p0.length() < 2) return List.of();

        String p1 = synonymService.canonicalProductOrSame(v1, p0);
        if (p1 == null || p1.isBlank() || p1.length() < 2) return List.of();

        List<CpeProduct> rows = productRepo.findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendor.getId(), p1);

        return rows.stream()
                .map(p -> new SuggestItem(
                        p.getNameNorm(),
                        (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName()
                ))
                .toList();
    }
}