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
    // Existing APIs (backward compatible)
    // =========================================================

    /**
     * Returns vendor suggestions for ID selector UI.
     * Search order: exact -> prefix -> contains.
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
     * Returns product suggestions for ID selector UI within a specific vendor.
     * Uses prefix search first, then falls back to contains search.
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

        // Fallback to contains search if no prefix match exists
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
     * Returns vendor suggestions for string-based search UI (e.g., unresolved mappings).
     * Search strategy:
     *   1) whole-string prefix
     *   2) whole-string contains
     *   3) token fallback (prefix / contains)
     */
    @GetMapping("/api/dict/vendors")
    public List<SuggestItem> suggestVendors(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        String v0 = normalizer.normalizeVendor(q);
        if (v0 == null || v0.isBlank() || v0.length() < minChars) return List.of();

        List<CpeVendor> rows = searchVendorsFlexible(v0, minChars, otherLimit);

        return rows.stream()
                .limit(otherLimit)
                .map(v -> new SuggestItem(
                        v.getNameNorm(),
                        (v.getDisplayName() == null || v.getDisplayName().isBlank()) ? v.getNameNorm() : v.getDisplayName()
                ))
                .toList();
    }

    /**
     * Returns product suggestions for string-based search UI.
     * Resolves vendor first (with token fallback), then searches products.
     */
    @GetMapping("/api/dict/products")
    public List<SuggestItem> suggestProducts(
            @RequestParam(name = "vendor", defaultValue = "") String vendorRaw,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        CpeVendor vendor = resolveVendorForProductSearch(vendorRaw, minChars);
        if (vendor == null) return List.of();

        String p0 = normalizer.normalizeProduct(q);
        if (p0 == null || p0.isBlank() || p0.length() < minChars) return List.of();

        List<CpeProduct> rows = searchProductsFlexible(vendor, p0, minChars, otherLimit);

        return rows.stream()
                .limit(otherLimit)
                .map(p -> new SuggestItem(
                        p.getNameNorm(),
                        (p.getDisplayName() == null || p.getDisplayName().isBlank()) ? p.getNameNorm() : p.getDisplayName()
                ))
                .toList();
    }

    /* =========================================================
     * Helper methods for flexible lookup and fallback handling
     * ========================================================= */

    private List<CpeVendor> searchVendorsFlexible(String rawNorm, int minChars, int limit) {
        Map<Long, CpeVendor> out = new LinkedHashMap<>();

        for (String candidate : expandQueriesForLookup(rawNorm, minChars)) {
            String canonical = synonymService.canonicalVendorOrSame(candidate);
            if (canonical == null || canonical.isBlank() || canonical.length() < minChars) continue;

            List<CpeVendor> prefix = vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc(canonical);
            appendVendors(out, prefix, limit);

            if (out.size() >= limit) break;

            if (prefix.isEmpty()) {
                List<CpeVendor> contains = vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc(canonical);
                appendVendors(out, contains, limit);
                if (out.size() >= limit) break;
            }
        }

        return new ArrayList<>(out.values());
    }

    private CpeVendor resolveVendorForProductSearch(String vendorRaw, int minChars) {
        String v0 = normalizer.normalizeVendor(vendorRaw);
        if (v0 == null || v0.isBlank()) return null;

        for (String candidate : expandQueriesForLookup(v0, minChars)) {
            String canonical = synonymService.canonicalVendorOrSame(candidate);
            if (canonical == null || canonical.isBlank()) continue;

            CpeVendor exact = vendorRepo.findByNameNorm(canonical).orElse(null);
            if (exact != null) return exact;

            List<CpeVendor> prefix = vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc(canonical);
            if (!prefix.isEmpty()) return prefix.get(0);

            List<CpeVendor> contains = vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc(canonical);
            if (!contains.isEmpty()) return contains.get(0);
        }

        return null;
    }

    private List<CpeProduct> searchProductsFlexible(CpeVendor vendor, String rawNorm, int minChars, int limit) {
        Map<Long, CpeProduct> out = new LinkedHashMap<>();

        for (String candidate : expandQueriesForLookup(rawNorm, minChars)) {
            String canonical = synonymService.canonicalProductOrSame(vendor.getNameNorm(), candidate);
            if (canonical == null || canonical.isBlank() || canonical.length() < minChars) continue;

            List<CpeProduct> prefix = productRepo
                    .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendor.getId(), canonical);
            appendProducts(out, prefix, limit);

            if (out.size() >= limit) break;

            if (prefix.isEmpty()) {
                List<CpeProduct> contains = productRepo
                        .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendor.getId(), canonical);
                appendProducts(out, contains, limit);
                if (out.size() >= limit) break;
            }
        }

        return new ArrayList<>(out.values());
    }

    private List<String> expandQueriesForLookup(String normalized, int minChars) {
        if (normalized == null || normalized.isBlank()) return List.of();

        List<String> queries = new ArrayList<>();
        putQuery(queries, normalized);

        String[] parts = normalized.trim().split("\\s+");
        if (parts.length <= 1) return queries;

        // Prioritize the last token
        putQuery(queries, parts[parts.length - 1]);

        // Add all tokens
        for (String part : parts) {
            if (part == null) continue;
            String s = part.trim();
            if (s.length() < minChars) continue;
            if (isNoiseToken(s)) continue;
            putQuery(queries, s);
        }

        return queries;
    }

    private void putQuery(List<String> queries, String q) {
        if (q == null) return;
        String s = q.trim();
        if (s.isEmpty()) return;
        if (!queries.contains(s)) {
            queries.add(s);
        }
    }

    private boolean isNoiseToken(String s) {
        return switch (s) {
            case "the", "and", "for", "with", "from", "inc", "inc.", "corp", "corp.", "co", "co.",
                 "ltd", "ltd.", "llc", "gmbh", "sa", "ag", "plc",
                 "software", "systems", "system", "developer", "developers",
                 "development", "community" -> true;
            default -> false;
        };
    }

    private void appendVendors(Map<Long, CpeVendor> out, List<CpeVendor> rows, int limit) {
        if (rows == null || rows.isEmpty()) return;
        for (CpeVendor row : rows) {
            if (row == null || row.getId() == null) continue;
            out.putIfAbsent(row.getId(), row);
            if (out.size() >= limit) return;
        }
    }

    private void appendProducts(Map<Long, CpeProduct> out, List<CpeProduct> rows, int limit) {
        if (rows == null || rows.isEmpty()) return;
        for (CpeProduct row : rows) {
            if (row == null || row.getId() == null) continue;
            out.putIfAbsent(row.getId(), row);
            if (out.size() >= limit) return;
        }
    }

    // =========================================================
    // New APIs for selector UI (grouped results)
    // =========================================================

    @GetMapping("/api/dict/vendors/search2")
    public SuggestGroupResponse searchVendorsByIdGrouped(
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int exactLimit = getInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        String v0 = normalizer.normalizeVendor(q);
        if (v0 == null || v0.isBlank() || v0.length() < minChars) {
            return new SuggestGroupResponse(List.of(), List.of());
        }

        return searchVendorsGroupedFlexible(v0, minChars, exactLimit, otherLimit);
    }

    @GetMapping("/api/dict/products/search2")
    public SuggestGroupResponse searchProductsByIdGrouped(
            @RequestParam(name = "vendorId") Long vendorId,
            @RequestParam(name = "q", defaultValue = "") String q
    ) {
        int minChars = getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        int exactLimit = getInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        int otherLimit = getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        if (vendorId == null) {
            return new SuggestGroupResponse(List.of(), List.of());
        }

        CpeVendor vendor = vendorRepo.findById(vendorId).orElse(null);
        if (vendor == null) {
            return new SuggestGroupResponse(List.of(), List.of());
        }

        String p0 = normalizer.normalizeProduct(q);
        if (p0 == null || p0.isBlank() || p0.length() < minChars) {
            return new SuggestGroupResponse(List.of(), List.of());
        }

        return searchProductsGroupedFlexible(vendor, p0, minChars, exactLimit, otherLimit);
    }

    // =========================================================
    // Resolve labels by IDs (preserve order)
    // =========================================================

    /**
     * Resolves vendor IDs to labels while preserving input order.
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
     * Resolves product IDs to labels while preserving input order.
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

    private SuggestGroupResponse searchVendorsGroupedFlexible(
            String rawNorm,
            int minChars,
            int exactLimit,
            int otherLimit
    ) {
        Map<Long, SuggestIdItem> exactMap = new LinkedHashMap<>();
        Map<Long, SuggestIdItem> otherMap = new LinkedHashMap<>();

        for (String candidate : expandQueriesForLookup(rawNorm, minChars)) {
            String canonical = synonymService.canonicalVendorOrSame(candidate);
            if (canonical == null || canonical.isBlank() || canonical.length() < minChars) continue;

            for (CpeVendor v : vendorRepo.findExact(canonical)) {
                putSuggest(exactMap, toSuggest(v), exactLimit);
                if (exactMap.size() >= exactLimit) break;
            }

            for (CpeVendor v : vendorRepo.findPrefixOrderByLength(canonical)) {
                putSuggest(otherMap, toSuggest(v), otherLimit);
                if (otherMap.size() >= otherLimit) break;
            }

            for (CpeVendor v : vendorRepo.findContainsOrderByLength(canonical)) {
                putSuggest(otherMap, toSuggest(v), otherLimit);
                if (otherMap.size() >= otherLimit) break;
            }

            if (exactMap.size() >= exactLimit && otherMap.size() >= otherLimit) {
                break;
            }
        }

        for (Long id : exactMap.keySet()) {
            otherMap.remove(id);
        }

        return new SuggestGroupResponse(
                new ArrayList<>(exactMap.values()),
                new ArrayList<>(otherMap.values())
        );
    }

    private SuggestGroupResponse searchProductsGroupedFlexible(
            CpeVendor vendor,
            String rawNorm,
            int minChars,
            int exactLimit,
            int otherLimit
    ) {
        Map<Long, SuggestIdItem> exactMap = new LinkedHashMap<>();
        Map<Long, SuggestIdItem> otherMap = new LinkedHashMap<>();

        for (String candidate : expandQueriesForLookup(rawNorm, minChars)) {
            String canonical = synonymService.canonicalProductOrSame(vendor.getNameNorm(), candidate);
            if (canonical == null || canonical.isBlank() || canonical.length() < minChars) continue;

            for (CpeProduct p : productRepo.findExactByVendorId(vendor.getId(), canonical)) {
                putSuggest(exactMap, toSuggestProduct(p), exactLimit);
                if (exactMap.size() >= exactLimit) break;
            }

            for (CpeProduct p : productRepo.findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendor.getId(), canonical)) {
                putSuggest(otherMap, toSuggestProduct(p), otherLimit);
                if (otherMap.size() >= otherLimit) break;
            }

            for (CpeProduct p : productRepo.findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(vendor.getId(), canonical)) {
                putSuggest(otherMap, toSuggestProduct(p), otherLimit);
                if (otherMap.size() >= otherLimit) break;
            }

            if (exactMap.size() >= exactLimit && otherMap.size() >= otherLimit) {
                break;
            }
        }

        for (Long id : exactMap.keySet()) {
            otherMap.remove(id);
        }

        return new SuggestGroupResponse(
                new ArrayList<>(exactMap.values()),
                new ArrayList<>(otherMap.values())
        );
    }

    private void putSuggest(Map<Long, SuggestIdItem> out, SuggestIdItem item, int limit) {
        if (item == null || item.id() == null) return;
        if (out.size() >= limit && !out.containsKey(item.id())) return;
        out.putIfAbsent(item.id(), item);
    }

    private static List<Long> parseIdCsv(String csv) {
        if (csv == null || csv.isBlank()) return List.of();

        List<Long> out = new ArrayList<>();
        for (String part : csv.split(",")) {
            if (part == null) continue;
            String s = part.trim();
            if (s.isEmpty()) continue;

            var m = ID_PREFIX.matcher(s);
            if (!m.find()) continue;

            try {
                out.add(Long.parseLong(m.group(1)));
            } catch (NumberFormatException ignore) {
                // Ignore invalid IDs
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