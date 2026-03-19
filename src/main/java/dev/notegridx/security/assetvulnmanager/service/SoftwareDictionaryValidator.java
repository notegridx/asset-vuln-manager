package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
public class SoftwareDictionaryValidator {

    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;

    public SoftwareDictionaryValidator(
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

    /**
     * Resolves raw vendor and product values to canonical CPE vendor/product IDs.
     *
     * Resolution flow:
     * 1. Normalize raw input values
     * 2. Apply synonym/alias resolution
     * 3. Resolve canonical vendor
     * 4. Resolve exact product within that vendor
     * 5. Optionally fall back to vendor-scoped token matching
     *
     * The method may return:
     * - hit: both vendor and product were resolved
     * - vendorOnly: vendor was resolved but product was not
     * - miss: resolution failed before a canonical vendor could be established
     */
    public Resolve resolve(String vendorRaw, String productRaw) {
        // Step 1: normalize raw input values before dictionary lookup.
        String v0 = normalizer.normalizeVendor(vendorRaw);
        String p0 = normalizer.normalizeProduct(productRaw);

        if (p0 == null) {
            return Resolve.miss(
                    DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_REQUIRED,
                    "product",
                    "Product is required.",
                    null,
                    null
            );
        }

        // Step 2: resolve aliases to canonical vendor/product names when possible.
        String v1 = synonymService.canonicalVendorOrSame(v0);
        String p1 = synonymService.canonicalProductOrSame(v1, p0);

        // Step 3: resolve canonical vendor from the dictionary.
        if (v1 == null || v1.isBlank()) {
            return Resolve.miss(
                    DictionaryValidationException.DictionaryErrorCode.DICT_VENDOR_REQUIRED,
                    "vendor",
                    "Vendor is required (CPE dictionary lookup).",
                    null,
                    p1
            );
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return Resolve.miss(
                    DictionaryValidationException.DictionaryErrorCode.DICT_VENDOR_NOT_FOUND,
                    "vendor",
                    "Vendor not found in CPE dictionary: " + v1,
                    v1,
                    p1
            );
        }

        Long vendorId = vendor.getId();

        // Step 4: attempt exact product resolution within the resolved vendor.
        CpeProduct prod = productRepo.findByVendorIdAndNameNorm(vendorId, p1).orElse(null);
        if (prod != null) {
            return Resolve.hit(vendorId, prod.getId(), v1, p1);
        }

        // Step 5: optionally try token-based fallback within the same vendor.
        // This fallback is intentionally guarded because some raw product strings
        // are too noisy or too opaque to use safely.
        if (shouldSkipTokenMatching(productRaw, p1)) {
            return Resolve.vendorOnly(
                    vendorId,
                    DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_NOT_FOUND,
                    "product",
                    "Product not found in CPE dictionary (token skipped): " + v1 + ":" + p1,
                    v1,
                    p1
            );
        }

        Optional<CpeProduct> best = bestProductByTokenOverlap(vendorId, p1);
        if (best.isPresent()) {
            CpeProduct bp = best.get();
            return Resolve.hit(vendorId, bp.getId(), v1, bp.getNameNorm());
        }

        return Resolve.vendorOnly(
                vendorId,
                DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_NOT_FOUND,
                "product",
                "Product not found in CPE dictionary: " + v1 + ":" + p1,
                v1,
                p1
        );
    }

    /**
     * Resolves vendor/product values and throws when the result is not a full hit.
     * This is useful for flows that require canonical vendor and product IDs
     * before proceeding.
     */
    public Resolve resolveOrThrow(String vendorRaw, String productRaw) {
        Resolve r = resolve(vendorRaw, productRaw);
        if (!r.hit()) {
            throw new DictionaryValidationException(
                    r.code(),
                    r.field(),
                    r.message(),
                    r.vendorNorm(),
                    r.productNorm()
            );
        }
        return r;
    }

    /**
     * Resolution result returned by dictionary validation.
     *
     * hit:
     *   Both vendorId and productId are resolved.
     *
     * vendorOnly:
     *   vendorId is resolved, but productId is not.
     *
     * miss:
     *   Resolution failed before a canonical vendor could be determined.
     */
    public record Resolve(
            boolean hit,
            Long vendorId,
            Long productId,
            String vendorNorm,
            String productNorm,
            DictionaryValidationException.DictionaryErrorCode code,
            String field,
            String message
    ) {
        public static Resolve hit(Long vendorId, Long productId, String vendorNorm, String productNorm) {
            return new Resolve(true, vendorId, productId, vendorNorm, productNorm, null, null, null);
        }

        /**
         * Returns a failure result where neither vendor nor product could be
         * resolved to canonical dictionary identifiers.
         */
        public static Resolve miss(
                DictionaryValidationException.DictionaryErrorCode code,
                String field,
                String message,
                String vendorNorm,
                String productNorm
        ) {
            return new Resolve(false, null, null, vendorNorm, productNorm, code, field, message);
        }

        /**
         * Returns a partial result where the vendor is resolved but the product
         * is not. This allows caller flows to keep vendor context for review,
         * suggestion, or later backfill.
         */
        public static Resolve vendorOnly(
                Long vendorId,
                DictionaryValidationException.DictionaryErrorCode code,
                String field,
                String message,
                String vendorNorm,
                String productNorm
        ) {
            return new Resolve(false, vendorId, null, vendorNorm, productNorm, code, field, message);
        }

        public boolean vendorOnly() {
            return !hit && vendorId != null && productId == null;
        }
    }

    // =========================================================
    // Token matching (vendor-scoped fallback)
    // =========================================================

    /**
     * Product strings that look like GUIDs are usually package identities,
     * not stable product names for dictionary matching.
     */
    private static final Pattern GUID =
            Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    /**
     * AppX- or Windows-style dotted identifiers are often too noisy for safe
     * token overlap matching and are therefore excluded from fallback matching.
     */
    private static final Pattern APPX_PREFIX =
            Pattern.compile("(?i)^(microsoft\\.|microsoftwindows\\.|windows\\.)");

    /**
     * Returns true when token-based fallback should be skipped because the raw
     * product string is too noisy or structurally unsuitable for safe matching.
     *
     * Current skip rules:
     * - blank raw product
     * - GUID-like identifiers
     * - AppX/Windows package-style prefixes
     * - strings containing many dots, which often indicate package identities
     */
    private boolean shouldSkipTokenMatching(String productRaw, String productNorm) {
        String pr = (productRaw == null) ? "" : productRaw.trim();
        if (pr.isEmpty()) return true;

        if (GUID.matcher(pr).matches()) return true;

        String pn = (productNorm == null) ? "" : productNorm.trim();
        if (!pn.isEmpty() && APPX_PREFIX.matcher(pn).find()) return true;

        int dotCount = 0;
        for (int i = 0; i < pr.length(); i++) {
            if (pr.charAt(i) == '.') dotCount++;
        }
        return dotCount >= 2;
    }

    /**
     * Attempts to find the best product candidate within a resolved vendor using
     * token overlap against canonical product names.
     *
     * Matching strategy:
     * - tokenize the normalized input
     * - pick a long token as the search anchor
     * - fetch a bounded candidate set using prefix/contains queries
     * - score candidates by token overlap and overlap ratio
     * - require minimum overlap and ratio thresholds before accepting
     *
     * This fallback is intentionally vendor-scoped to reduce false positives.
     */
    private Optional<CpeProduct> bestProductByTokenOverlap(Long vendorId, String productNorm) {
        if (vendorId == null) return Optional.empty();
        if (productNorm == null || productNorm.isBlank()) return Optional.empty();

        List<String> tokens = tokenize(productNorm);
        if (tokens.size() < 2) return Optional.empty();

        String anchor = tokens.stream()
                .filter(t -> t.length() >= 3)
                .max(Comparator.comparingInt(String::length))
                .orElse(tokens.get(0));

        List<CpeProduct> cands = new ArrayList<>();
        cands.addAll(productRepo.findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendorId, anchor));
        cands.addAll(productRepo.findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(vendorId, anchor));

        if (cands.isEmpty()) return Optional.empty();

        Set<String> tokenSet = new HashSet<>(tokens);

        CpeProduct best = null;
        int bestOverlap = -1;
        double bestRatio = -1.0;

        for (CpeProduct p : cands) {
            String candNorm = p.getNameNorm();
            if (candNorm == null || candNorm.isBlank()) continue;

            List<String> ct = tokenize(candNorm);
            if (ct.isEmpty()) continue;

            int overlap = 0;
            for (String t : ct) {
                if (tokenSet.contains(t)) overlap++;
            }

            double ratio = overlap / (double) Math.max(tokens.size(), ct.size());

            if (overlap > bestOverlap
                    || (overlap == bestOverlap && ratio > bestRatio)
                    || (overlap == bestOverlap && ratio == bestRatio
                    && best != null && candNorm.length() < best.getNameNorm().length())) {
                best = p;
                bestOverlap = overlap;
                bestRatio = ratio;
            }
        }

        if (best == null) return Optional.empty();

        // Require both absolute overlap and relative overlap to keep fallback conservative.
        if (bestOverlap >= 2 && bestRatio >= 0.60) {
            return Optional.of(best);
        }
        return Optional.empty();
    }

    /**
     * Splits a normalized product string into comparison tokens.
     * Very short tokens are ignored because they add noise and increase
     * the chance of accidental overlap.
     */
    private List<String> tokenize(String norm) {
        if (norm == null) return List.of();
        String x = norm.trim();
        if (x.isEmpty()) return List.of();

        String[] parts = x.split("[\\s._\\-]+");
        ArrayList<String> out = new ArrayList<>();
        for (String p : parts) {
            if (p == null) continue;
            String t = p.trim();
            if (t.isEmpty()) continue;
            if (t.length() <= 1) continue;
            out.add(t);
        }
        return out;
    }
}