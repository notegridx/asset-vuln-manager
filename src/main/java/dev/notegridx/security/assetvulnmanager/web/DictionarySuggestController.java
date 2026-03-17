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
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import dev.notegridx.security.assetvulnmanager.service.VendorProductNormalizer;

import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_CANDIDATE_EXACT_LIMIT;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_CANDIDATE_MIN_CHARS;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_CANDIDATE_OTHER_LIMIT;

@RestController
public class DictionarySuggestController {

    private static final Pattern ID_PREFIX = Pattern.compile("^(\\d+)");

    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;
    private final SystemSettingRepository systemSettingRepository;

    public DictionarySuggestController(
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            VendorProductNormalizer normalizer,
            SynonymService synonymService,
            SystemSettingRepository systemSettingRepository
    ) {
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.normalizer = normalizer;
        this.synonymService = synonymService;
        this.systemSettingRepository = systemSettingRepository;
    }

    public record SuggestItem(String value, String label) {}

    public record SuggestIdItem(Long id, String label, String nameNorm) {}

    /**
     * Grouped response for selector UI (exact matches first, then other candidates).
     */
    public record SuggestGroupResponse(
            List<SuggestIdItem> exact,
            List<SuggestIdItem> others
    ) {}

    // =========================================================
    // Existing APIs (keep backward compatibility)
    // =========================================================

    /**
     * Vendor suggestions for ID selector UI.
     * Search order: exact -> prefix -> contains
     */
    @GetMapping("/api/dict/vendors/search")
    public List<SuggestIdItem> searchVendorsById(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int exactLimit = getInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        String v = normalizer.normalizeVendor(q);
        if (v == null || v.length() < minChars) return List.of();

        var exact = vendorRepo.findExact(v);
        if (!exact.isEmpty()) {
            return exact.stream().limit(exactLimit).map(this::toSuggest).toList();
        }

        var prefix = vendorRepo.findPrefixOrderByLength(v);
        if (!prefix.isEmpty()) {
            return prefix.stream().limit(otherLimit).map(this::toSuggest).toList();
        }

        return vendorRepo.findContainsOrderByLength(v).stream()
                .limit(otherLimit)
                .map(this::toSuggest)
                .toList();
    }

    /**
     * Product suggestions for ID selector UI.
     * Search within the selected vendor using prefix match,
     * then fall back to contains match when no prefix hit exists.
     */
    @GetMapping("/api/dict/products/search")
    public List<SuggestIdItem> searchProductsById(
            @RequestParam(name = "vendorId") Long vendorId,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        if (vendorId == null) return List.of();

        String p0 = normalizer.normalizeProduct(q);
        if (p0 == null || p0.isBlank() || p0.length() < minChars) return List.of();

        List<CpeProduct> rows = productRepo
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendorId, p0);

        // Fallback to contains search when no prefix match exists.
        if (rows.isEmpty()) {
            rows = productRepo
                    .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendorId, p0);
        }

        return rows.stream()
                .limit(otherLimit)
                .map(p -> new SuggestIdItem(
                        p.getId(),
                        (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName(),
                        p.getNameNorm()
                ))
                .toList();
    }

    /**
     * Vendor suggestions for string-based search UI such as unresolved mappings.
     * Search uses prefix match first and falls back to contains match.
     *
     * Example: GET /api/dict/vendors?q=mic
     */
    @GetMapping("/api/dict/vendors")
    public List<SuggestItem> suggestVendors(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        String v0 = normalizer.normalizeVendor(q);
        if (v0 == null || v0.isBlank() || v0.length() < minChars) return List.of();

        String v1 = synonymService.canonicalVendorOrSame(v0);
        if (v1 == null || v1.isBlank() || v1.length() < minChars) return List.of();

        List<CpeVendor> rows = vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc(v1);

        // Fallback to contains search when no prefix match exists.
        if (rows.isEmpty()) {
            rows = vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc(v1);
        }

        return rows.stream()
                .limit(otherLimit)
                .map(v -> new SuggestItem(
                        v.getNameNorm(),
                        (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName()
                ))
                .toList();
    }

    /**
     * Product suggestions for string-based search UI such as unresolved mappings.
     * Resolve the vendor first, then search products under that vendor
     * using prefix match and fall back to contains match.
     *
     * Example: GET /api/dict/products?vendor=microsoft&q=ed
     */
    @GetMapping("/api/dict/products")
    public List<SuggestItem> suggestProducts(
            @RequestParam(name = "vendor", defaultValue = "") String vendorRaw,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        String v0 = normalizer.normalizeVendor(vendorRaw);
        if (v0 == null || v0.isBlank()) return List.of();

        String v1 = synonymService.canonicalVendorOrSame(v0);
        if (v1 == null || v1.isBlank()) return List.of();

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) return List.of();

        String p0 = normalizer.normalizeProduct(q);
        if (p0 == null || p0.isBlank() || p0.length() < minChars) return List.of();

        String p1 = synonymService.canonicalProductOrSame(v1, p0);
        if (p1 == null || p1.isBlank() || p1.length() < minChars) return List.of();

        List<CpeProduct> rows = productRepo
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendor.getId(), p1);

        // Fallback to contains search when no prefix match exists.
        if (rows.isEmpty()) {
            rows = productRepo
                    .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendor.getId(), p1);
        }

        return rows.stream()
                .limit(otherLimit)
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
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int exactLimit = getInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        String v = normalizer.normalizeVendor(q);
        if (v == null || v.length() < minChars) return new SuggestGroupResponse(List.of(), List.of());

        // Exact matches.
        List<SuggestIdItem> exact = vendorRepo.findExact(v).stream()
                .limit(exactLimit)
                .map(this::toSuggest)
                .toList();

        // Other candidates: prefix first, then contains.
        List<CpeVendor> prefix = vendorRepo.findPrefixOrderByLength(v);
        List<CpeVendor> contains = vendorRepo.findContainsOrderByLength(v);

        List<SuggestIdItem> others = dedupeVendors(exact, prefix, contains, otherLimit);
        return new SuggestGroupResponse(exact, others);
    }

    @GetMapping("/api/dict/products/search2")
    public SuggestGroupResponse searchProductsByIdGrouped(
            @RequestParam(name = "vendorId") Long vendorId,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int exactLimit = getInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        if (vendorId == null) return new SuggestGroupResponse(List.of(), List.of());

        String p = normalizer.normalizeProduct(q);
        if (p == null || p.length() < minChars) return new SuggestGroupResponse(List.of(), List.of());

        // Exact matches within the selected vendor.
        List<CpeProduct> exactRows = productRepo.findExactByVendorId(vendorId, p);
        List<SuggestIdItem> exact = exactRows.stream()
                .limit(exactLimit)
                .map(this::toSuggestProduct)
                .toList();

        // Other candidates: prefix first, then contains.
        List<CpeProduct> prefix = productRepo.findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendorId, p);
        List<CpeProduct> contains = productRepo.findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(vendorId, p);

        List<SuggestIdItem> others = dedupeProducts(exact, prefix, contains, otherLimit);
        return new SuggestGroupResponse(exact, others);
    }

    // =========================================================
    // New APIs: resolve labels by IDs (for quick candidates)
    // =========================================================

    /**
     * Resolve vendor IDs to label/nameNorm while preserving input order.
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
     * Resolve product IDs to label/nameNorm while preserving input order.
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

    private int getInt(String key, int defaultValue) {
        return systemSettingRepository.findById(key)
                .map(s -> s.getSettingValue())
                .map(v -> {
                    try {
                        return Integer.parseInt(v);
                    } catch (Exception e) {
                        return defaultValue;
                    }
                })
                .orElse(defaultValue);
    }

    private static List<Long> parseIdCsv(String csv) {
        if (csv == null || csv.isBlank()) return List.of();

        List<Long> out = new ArrayList<>();
        for (String part : csv.split(",")) {
            if (part == null) continue;
            String s = part.trim();
            if (s.isEmpty()) continue;

            // Migration-friendly: allow formats such as "97:google".
            var m = ID_PREFIX.matcher(s);
            if (!m.find()) continue;

            try {
                out.add(Long.parseLong(m.group(1)));
            } catch (NumberFormatException ignore) {
                // Ignore invalid IDs.
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

        // Remove exact matches from the "others" list.
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

        // Remove exact matches from the "others" list.
        for (SuggestIdItem e : exact) map.remove(e.id());

        List<SuggestIdItem> out = new ArrayList<>(map.values());
        return out.size() <= limit ? out : out.subList(0, limit);
    }
}