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

    public Resolve resolve(String vendorRaw, String productRaw) {
        // 1) normalize
        String v0 = normalizer.normalizeVendor(vendorRaw);
        String p0 = normalizer.normalizeProduct(productRaw);

        if (p0 == null) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_PRODUCT_REQUIRED,
                    "product", "Product is required.", null, null);
        }

        // 2) synonym
        String v1 = synonymService.canonicalVendorOrSame(v0);
        String p1 = synonymService.canonicalProductOrSame(v1, p0);

        // 3) dictionary lookup (vendor)
        if (v1 == null || v1.isBlank()) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_VENDOR_REQUIRED,
                    "vendor", "Vendor is required (CPE dictionary lookup).", null, p1);
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return Resolve.miss(DictionaryValidationException.DictionaryErrorCode.DICT_VENDOR_NOT_FOUND,
                    "vendor", "Vendor not found in CPE dictionary: " + v1, v1, p1);
        }

        Long vendorId = vendor.getId();

        // 4) exact product within vendor
        CpeProduct prod = productRepo.findByVendorIdAndNameNorm(vendorId, p1).orElse(null);
        if (prod != null) {
            return Resolve.hit(vendorId, prod.getId(), v1, p1);
        }

        // 5) fallback: token matching within vendor (safe guard)
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

        /** vendorId/productId ともに不明（vendor未入力、vendor辞書なし等） */
        public static Resolve miss(
                DictionaryValidationException.DictionaryErrorCode code,
                String field,
                String message,
                String vendorNorm,
                String productNorm
        ) {
            return new Resolve(false, null, null, vendorNorm, productNorm, code, field, message);
        }

        /** vendor は辞書で確定したが product が確定しない（hit=false だが vendorId は返す） */
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

    private static final Pattern GUID =
            Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern APPX_PREFIX =
            Pattern.compile("(?i)^(microsoft\\.|microsoftwindows\\.|windows\\.)");

    private boolean shouldSkipTokenMatching(String productRaw, String productNorm) {
        String pr = (productRaw == null) ? "" : productRaw.trim();
        if (pr.isEmpty()) return true;

        if (GUID.matcher(pr).matches()) return true;

        String pn = (productNorm == null) ? "" : productNorm.trim();
        if (!pn.isEmpty() && APPX_PREFIX.matcher(pn).find()) return true;

        int dotCount = 0;
        for (int i = 0; i < pr.length(); i++) if (pr.charAt(i) == '.') dotCount++;
        return dotCount >= 2;
    }

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
            for (String t : ct) if (tokenSet.contains(t)) overlap++;

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

        if (bestOverlap >= 2 && bestRatio >= 0.60) {
            return Optional.of(best);
        }
        return Optional.empty();
    }

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