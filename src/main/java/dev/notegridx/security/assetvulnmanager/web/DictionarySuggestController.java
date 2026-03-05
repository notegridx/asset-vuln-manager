package dev.notegridx.security.assetvulnmanager.web;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

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

    private static final Pattern ID_PREFIX = Pattern.compile("^(\\d+)");

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

    public record SuggestIdItem(Long id, String label, String nameNorm) {}

    /**
     * Grouped response for selector UI (exact first, then others)
     */
    public record SuggestGroupResponse(
            List<SuggestIdItem> exact,
            List<SuggestIdItem> others
    ) {}

    // =========================================================
    // Existing APIs (keep backward compatibility)
    // =========================================================

    /**
     * Vendor候補（ID selector用）
     * exact -> prefix -> contains
     */
    @GetMapping("/api/dict/vendors/search")
    public List<SuggestIdItem> searchVendorsById(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        String v = normalizer.normalizeVendor(q);
        if (v == null || v.length() < 2) return List.of();

        var exact = vendorRepo.findExact(v);
        if (!exact.isEmpty()) {
            return exact.stream().limit(10).map(this::toSuggest).toList();
        }

        var prefix = vendorRepo.findPrefixOrderByLength(v);
        if (!prefix.isEmpty()) {
            return prefix.stream().limit(15).map(this::toSuggest).toList();
        }

        return vendorRepo.findContainsOrderByLength(v).stream()
                .limit(10)
                .map(this::toSuggest)
                .toList();
    }

    /**
     * Product候補（ID selector用）
     * vendorId配下で prefix（0件なら contains）にフォールバック
     */
    @GetMapping("/api/dict/products/search")
    public List<SuggestIdItem> searchProductsById(
            @RequestParam(name = "vendorId") Long vendorId,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        if (vendorId == null) return List.of();

        String p0 = normalizer.normalizeProduct(q);
        if (p0 == null || p0.isBlank() || p0.length() < 2) return List.of();

        List<CpeProduct> rows = productRepo
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendorId, p0);

        // fallback: contains
        if (rows.isEmpty()) {
            rows = productRepo
                    .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendorId, p0);
        }

        return rows.stream()
                .map(p -> new SuggestIdItem(
                        p.getId(),
                        (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName(),
                        p.getNameNorm()
                ))
                .toList();
    }

    /**
     * Vendor候補（unresolved等の文字列検索用）
     * prefix（0件なら contains）にフォールバック
     *
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

        // fallback: contains
        if (rows.isEmpty()) {
            rows = vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc(v1);
        }

        return rows.stream()
                .map(v -> new SuggestItem(
                        v.getNameNorm(),
                        (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName()
                ))
                .toList();
    }

    /**
     * Product候補（unresolved等の文字列検索用）
     * vendor確定 → vendor配下の product を prefix（0件なら contains）にフォールバック
     *
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

        List<CpeProduct> rows = productRepo
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendor.getId(), p1);

        // fallback: contains
        if (rows.isEmpty()) {
            rows = productRepo
                    .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendor.getId(), p1);
        }

        return rows.stream()
                .map(p -> new SuggestItem(
                        p.getNameNorm(),
                        (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName()
                ))
                .toList();
    }

    // =========================================================
    // New APIs for selector UI (grouped: exact first, then others)
    // =========================================================

    @GetMapping("/api/dict/vendors/search2")
    public SuggestGroupResponse searchVendorsByIdGrouped(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        String v = normalizer.normalizeVendor(q);
        if (v == null || v.length() < 2) return new SuggestGroupResponse(List.of(), List.of());

        // exact
        List<SuggestIdItem> exact = vendorRepo.findExact(v).stream()
                .limit(5)
                .map(this::toSuggest)
                .toList();

        // others: prefix (shorter first), then contains
        List<CpeVendor> prefix = vendorRepo.findPrefixOrderByLength(v);
        List<CpeVendor> contains = vendorRepo.findContainsOrderByLength(v);

        List<SuggestIdItem> others = dedupeVendors(exact, prefix, contains, 30);
        return new SuggestGroupResponse(exact, others);
    }

    @GetMapping("/api/dict/products/search2")
    public SuggestGroupResponse searchProductsByIdGrouped(
            @RequestParam(name = "vendorId") Long vendorId,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        if (vendorId == null) return new SuggestGroupResponse(List.of(), List.of());

        String p = normalizer.normalizeProduct(q);
        if (p == null || p.length() < 2) return new SuggestGroupResponse(List.of(), List.of());

        // exact within vendor
        List<CpeProduct> exactRows = productRepo.findExactByVendorId(vendorId, p);
        List<SuggestIdItem> exact = exactRows.stream()
                .limit(5)
                .map(this::toSuggestProduct)
                .toList();

        // others: prefix then contains
        List<CpeProduct> prefix = productRepo.findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendorId, p);
        List<CpeProduct> contains = productRepo.findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(vendorId, p);

        List<SuggestIdItem> others = dedupeProducts(exact, prefix, contains, 30);
        return new SuggestGroupResponse(exact, others);
    }

    // =========================================================
    // New APIs: resolve labels by IDs (for quick candidates)
    // =========================================================

    /**
     * Resolve vendor IDs -> label/nameNorm (preserve input order).
     * Example: GET /api/dict/vendors/by-ids?ids=97,11961,8623
     */
    @GetMapping("/api/dict/vendors/by-ids")
    public List<SuggestIdItem> vendorsByIds(
            @RequestParam(name = "ids", defaultValue = "") String idsCsv
    ) {
        List<Long> ids = parseIdCsv(idsCsv);
        if (ids.isEmpty()) return List.of();

        var found = vendorRepo.findAllById(ids);
        Map<Long, CpeVendor> map = new LinkedHashMap<>();
        for (CpeVendor v : found) {
            map.put(v.getId(), v);
        }

        List<SuggestIdItem> out = new ArrayList<>();
        for (Long id : ids) {
            CpeVendor v = map.get(id);
            if (v != null) out.add(toSuggest(v));
        }
        return out;
    }

    /**
     * Resolve product IDs -> label/nameNorm (preserve input order).
     * Example: GET /api/dict/products/by-ids?ids=123,456
     */
    @GetMapping("/api/dict/products/by-ids")
    public List<SuggestIdItem> productsByIds(
            @RequestParam(name = "ids", defaultValue = "") String idsCsv
    ) {
        List<Long> ids = parseIdCsv(idsCsv);
        if (ids.isEmpty()) return List.of();

        var found = productRepo.findAllById(ids);
        Map<Long, CpeProduct> map = new LinkedHashMap<>();
        for (CpeProduct p : found) {
            map.put(p.getId(), p);
        }

        List<SuggestIdItem> out = new ArrayList<>();
        for (Long id : ids) {
            CpeProduct p = map.get(id);
            if (p != null) out.add(toSuggestProduct(p));
        }
        return out;
    }

    // =========================================================
    // Helpers
    // =========================================================

    private static List<Long> parseIdCsv(String csv) {
        if (csv == null || csv.isBlank()) return List.of();

        List<Long> out = new ArrayList<>();
        for (String part : csv.split(",")) {
            if (part == null) continue;
            String s = part.trim();
            if (s.isEmpty()) continue;

            // migration-friendly: allow "97:google"
            var m = ID_PREFIX.matcher(s);
            if (!m.find()) continue;

            try {
                out.add(Long.parseLong(m.group(1)));
            } catch (NumberFormatException ignore) {
                // ignore invalid
            }
        }
        return out;
    }

    private SuggestIdItem toSuggest(CpeVendor v) {
        String label = (v.getDisplayName() == null || v.getDisplayName().isBlank())
                ? v.getNameNorm()
                : v.getDisplayName();
        return new SuggestIdItem(v.getId(), label, v.getNameNorm());
    }

    private SuggestIdItem toSuggestProduct(CpeProduct p) {
        String label = (p.getDisplayName() == null || p.getDisplayName().isBlank())
                ? p.getNameNorm()
                : p.getDisplayName();
        return new SuggestIdItem(p.getId(), label, p.getNameNorm());
    }

    private static List<SuggestIdItem> dedupeVendors(
            List<SuggestIdItem> exact,
            List<CpeVendor> prefix,
            List<CpeVendor> contains,
            int limit
    ) {
        Map<Long, SuggestIdItem> map = new LinkedHashMap<>();
        for (SuggestIdItem e : exact) {
            map.put(e.id(), e);
        }
        for (CpeVendor v : prefix) {
            map.putIfAbsent(v.getId(), new SuggestIdItem(
                    v.getId(),
                    (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName(),
                    v.getNameNorm()
            ));
        }
        for (CpeVendor v : contains) {
            map.putIfAbsent(v.getId(), new SuggestIdItem(
                    v.getId(),
                    (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName(),
                    v.getNameNorm()
            ));
        }
        // drop exact from others
        for (SuggestIdItem e : exact) map.remove(e.id());

        List<SuggestIdItem> out = new ArrayList<>(map.values());
        return out.size() <= limit ? out : out.subList(0, limit);
    }

    private static List<SuggestIdItem> dedupeProducts(
            List<SuggestIdItem> exact,
            List<CpeProduct> prefix,
            List<CpeProduct> contains,
            int limit
    ) {
        Map<Long, SuggestIdItem> map = new LinkedHashMap<>();
        for (SuggestIdItem e : exact) {
            map.put(e.id(), e);
        }
        for (CpeProduct p : prefix) {
            map.putIfAbsent(p.getId(), new SuggestIdItem(
                    p.getId(),
                    (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName(),
                    p.getNameNorm()
            ));
        }
        for (CpeProduct p : contains) {
            map.putIfAbsent(p.getId(), new SuggestIdItem(
                    p.getId(),
                    (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName(),
                    p.getNameNorm()
            ));
        }
        for (SuggestIdItem e : exact) map.remove(e.id());

        List<SuggestIdItem> out = new ArrayList<>(map.values());
        return out.size() <= limit ? out : out.subList(0, limit);
    }
}