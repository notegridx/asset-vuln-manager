package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

@Slf4j
@Service
public class CanonicalCpeLinkingService {

    private final SoftwareInstallRepository softwareRepo;
    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;
    private final TokenMatchingService tokenMatchingService;

    public CanonicalCpeLinkingService(
            SoftwareInstallRepository softwareRepo,
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            VendorProductNormalizer normalizer,
            SynonymService synonymService,
            TokenMatchingService tokenMatchingService
    ) {
        this.softwareRepo = softwareRepo;
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.normalizer = normalizer;
        this.synonymService = synonymService;
        this.tokenMatchingService = tokenMatchingService;
    }

    // ------------------------------------------------------------
    // Public: stats
    //  - Dictionary buckets are ONLY for "not linked" (no vendor_id & no product_id)
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public MappingStats stats(Collection<SoftwareInstall> rows) {
        int total = 0;

        // SQL link axis
        int vendorOnlyLinkedSql = 0;
        int fullyLinkedSql = 0;
        int notLinkedSql = 0;

        // fully linked quality
        int linkedValid = 0;
        int linkedStale = 0;

        // dictionary resolution (ONLY for notLinkedSql)
        int fullyResolvable = 0;
        int vendorResolvableOnly = 0;
        int unresolvable = 0;

        int needsNorm = 0;

        for (SoftwareInstall s : rows) {
            total++;

            Analysis a = analyze(s);

            if (a.needsNormalization()) needsNorm++;

            if (a.vendorOnlyLinkedSql()) vendorOnlyLinkedSql++;
            if (a.fullyLinkedSql()) fullyLinkedSql++;
            if (a.notLinkedSql()) notLinkedSql++;

            if (a.result() == ItemResult.LINKED) linkedValid++;
            if (a.result() == ItemResult.STALE) linkedStale++;

            if (a.dictFullyResolvable()) fullyResolvable++;
            if (a.dictVendorResolvableOnly()) vendorResolvableOnly++;
            if (a.dictUnresolvable()) unresolvable++;
        }

        return new MappingStats(
                total,
                fullyLinkedSql,
                vendorOnlyLinkedSql,
                notLinkedSql,
                linkedValid,
                linkedStale,
                fullyResolvable,
                vendorResolvableOnly,
                unresolvable,
                needsNorm
        );
    }

    /**
     * Overall stats (first N rows).
     */
    @Transactional(readOnly = true)
    public MappingStats statsOverall(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 5000));
        List<SoftwareInstall> rows = softwareRepo.findAll().stream().limit(safeLimit).toList();
        return stats(rows);
    }

    // ------------------------------------------------------------
    // Public: analysis (LINKED / RESOLVED / STALE / UNRESOLVED)
    //  - LINKED/STALE: "fully linked" (vendor+product both present)
    //  - RESOLVED: not fully linked, and dictionary fully resolves vendor+product
    //  - UNRESOLVED: otherwise
    //
    //  NOTE: Dictionary buckets (Fully/Vendor-only/Unresolvable) are computed
    //        ONLY when "not linked" (neither vendor_id nor product_id is set).
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public Analysis analyze(SoftwareInstall s) {

        boolean vendorLinked = (s.getCpeVendorId() != null);
        boolean productLinked = (s.getCpeProductId() != null);

        boolean fullyLinked = vendorLinked && productLinked;
        boolean vendorOnlyLinked = vendorLinked && !productLinked;
        boolean notLinked = !vendorLinked && !productLinked;

        // Dictionary resolvability from strings (existing behavior)
        ResolveResult r = resolve(s);

        // Dictionary buckets are ONLY for "not linked"
        boolean dictFullyResolvable = notLinked && r.hit();
        boolean dictVendorOnlyResolvable = notLinked && r.vendorOnly();
        boolean dictUnresolvable = notLinked && !r.hit() && !r.vendorOnly();

        // Fully linked: validate referenced dictionary rows still exist.
        if (fullyLinked) {
            boolean vendorOk = vendorRepo.existsById(s.getCpeVendorId());
            boolean prodOk = productRepo.existsById(s.getCpeProductId());

            if (vendorOk && prodOk) {
                return Analysis.linkedOk(r, null,
                        vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                        dictFullyResolvable, dictVendorOnlyResolvable, dictUnresolvable);
            }

            String reason = "linked IDs are stale: vendorOk=" + vendorOk + ", productOk=" + prodOk;
            return Analysis.stale(r, reason,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFullyResolvable, dictVendorOnlyResolvable, dictUnresolvable);
        }

        // Not fully linked:
        if (r.hit()) {
            // RESOLVED = vendor+product fully resolvable (even if vendor is already linked, this is still actionable)
            return Analysis.resolved(r, null,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFullyResolvable, dictVendorOnlyResolvable, dictUnresolvable);
        }

        // UNRESOLVED
        // vendor-only のときは理由を少し補強（UIで見たとき納得感が出る）
        String reason = r.reason();
        if (vendorOnlyLinked) {
            reason = (reason == null || reason.isBlank())
                    ? "Vendor is linked, but product is not resolvable from normalized strings."
                    : ("Vendor is linked, but product is not resolvable: " + reason);
        } else if (notLinked && r.vendorOnly()) {
            reason = (reason == null || reason.isBlank())
                    ? "Vendor is resolvable, but product is not."
                    : ("Vendor is resolvable, but product is not: " + reason);
        }

        return Analysis.unresolved(r, reason,
                vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                dictFullyResolvable, dictVendorOnlyResolvable, dictUnresolvable);
    }

    public enum ItemResult {
        LINKED,      // fully linked and IDs are valid
        RESOLVED,    // not fully linked, but dictionary can fully resolve vendor+product
        STALE,       // fully linked, but referenced dictionary rows missing
        UNRESOLVED   // otherwise
    }

    public record MappingStats(
            int total,

            // SQL link axis
            int fullyLinkedSql,
            int vendorOnlyLinkedSql,
            int notLinkedSql,

            // fully linked quality
            int linkedValid,
            int linkedStale,

            // dictionary resolution (ONLY for notLinkedSql)
            int fullyResolvable,
            int vendorResolvableOnly,
            int unresolvable,

            int needsNormalization
    ) {}

    public record Analysis(
            ItemResult result,
            String reason,
            boolean needsNormalization,
            ResolveResult resolve,

            // SQL link visibility
            boolean vendorLinkedSql,
            boolean productLinkedSql,
            boolean fullyLinkedSql,
            boolean vendorOnlyLinkedSql,
            boolean notLinkedSql,

            // dictionary buckets (ONLY meaningful when notLinkedSql=true)
            boolean dictFullyResolvable,
            boolean dictVendorResolvableOnly,
            boolean dictUnresolvable
    ) {
        static Analysis linkedOk(ResolveResult r, String reason,
                                 boolean vendorLinked, boolean productLinked, boolean fullyLinked,
                                 boolean vendorOnlyLinked, boolean notLinked,
                                 boolean dictFully, boolean dictVendorOnly, boolean dictUnresolvable) {
            return new Analysis(ItemResult.LINKED, reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFully, dictVendorOnly, dictUnresolvable);
        }

        static Analysis resolved(ResolveResult r, String reason,
                                 boolean vendorLinked, boolean productLinked, boolean fullyLinked,
                                 boolean vendorOnlyLinked, boolean notLinked,
                                 boolean dictFully, boolean dictVendorOnly, boolean dictUnresolvable) {
            return new Analysis(ItemResult.RESOLVED, reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFully, dictVendorOnly, dictUnresolvable);
        }

        static Analysis stale(ResolveResult r, String reason,
                              boolean vendorLinked, boolean productLinked, boolean fullyLinked,
                              boolean vendorOnlyLinked, boolean notLinked,
                              boolean dictFully, boolean dictVendorOnly, boolean dictUnresolvable) {
            return new Analysis(ItemResult.STALE, reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFully, dictVendorOnly, dictUnresolvable);
        }

        static Analysis unresolved(ResolveResult r, String reason,
                                   boolean vendorLinked, boolean productLinked, boolean fullyLinked,
                                   boolean vendorOnlyLinked, boolean notLinked,
                                   boolean dictFully, boolean dictVendorOnly, boolean dictUnresolvable) {
            return new Analysis(ItemResult.UNRESOLVED, reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFully, dictVendorOnly, dictUnresolvable);
        }
    }

    // ------------------------------------------------------------
    // resolve (string -> dictionary lookup)
    //  - exact vendor/product (after synonym)
    //  - fallback: product token matching within vendor
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public ResolveResult resolve(SoftwareInstall s) {
        String v0 = normalizer.normalizeVendor(bestEffortVendor(s));
        String p0 = normalizer.normalizeProduct(s.getProduct());

        boolean needsNorm = (s.getNormalizedProduct() == null || s.getNormalizedProduct().isBlank());

        if (p0 == null) {
            return ResolveResult.miss("product is blank after normalize", needsNorm, null, null, null);
        }

        String v1 = synonymService.canonicalVendorOrSame(v0);
        String p1 = synonymService.canonicalProductOrSame(v1, p0);

        if (v1 == null || v1.isBlank()) {
            return ResolveResult.miss("vendor missing (cannot lookup cpe_products)", needsNorm, null, null, p1);
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return ResolveResult.miss("vendor not found in cpe_vendors: " + v1, needsNorm, null, v1, p1);
        }

        Long vendorId = vendor.getId();

        CpeProduct prod = productRepo.findByVendorIdAndNameNorm(vendorId, p1).orElse(null);
        if (prod != null) {
            return ResolveResult.hit(vendorId, prod.getId(), v1, p1, needsNorm);
        }

        if (shouldSkipTokenMatching(s.getProduct(), p1)) {
            if (log.isDebugEnabled()) {
                log.debug("CPE token-match skipped: swId={}, vendorNorm={}, productNorm={}, productRaw='{}'",
                        safeId(s), v1, p1, safeStr(s.getProduct()));
            }
            return ResolveResult.vendorOnly(
                    vendorId, v1, p1,
                    "product not found (token-matching skipped): " + v1 + ":" + p1,
                    needsNorm
            );
        }

        Optional<CpeProduct> best = tokenMatchingService.bestProduct(vendorId, p1);
        if (best.isPresent()) {
            CpeProduct bp = best.get();
            if (log.isDebugEnabled()) {
                log.debug("CPE token-match HIT: swId={}, vendorId={}, vendorNorm={}, inputProductNorm={}, matchedProductId={}, matchedProductNorm={}",
                        safeId(s), vendorId, v1, p1, bp.getId(), bp.getNameNorm());
            }
            return ResolveResult.hit(vendorId, bp.getId(), v1, bp.getNameNorm(), needsNorm);
        }

        if (log.isDebugEnabled()) {
            log.debug("CPE token-match MISS: swId={}, vendorId={}, vendorNorm={}, productNorm={}, productRaw='{}'",
                    safeId(s), vendorId, v1, p1, safeStr(s.getProduct()));
        }

        return ResolveResult.vendorOnly(
                vendorId, v1, p1,
                "product not found in cpe_products: " + v1 + ":" + p1,
                needsNorm
        );
    }

    private static String bestEffortVendor(SoftwareInstall s) {
        String v = s.getVendor();
        if (v == null) return null;
        String t = v.trim();
        return t.isEmpty() ? null : t;
    }

    public record ResolveResult(
            boolean hit,
            Long vendorId,
            Long productId,
            String vendorNorm,
            String productNorm,
            String reason,
            boolean needsNormalization
    ) {
        public static ResolveResult hit(Long vId, Long pId, String vNorm, String pNorm, boolean needsNorm) {
            return new ResolveResult(true, vId, pId, vNorm, pNorm, null, needsNorm);
        }

        public static ResolveResult miss(String reason, boolean needsNorm, Long vendorId, String vNorm, String pNorm) {
            return new ResolveResult(false, vendorId, null, vNorm, pNorm, reason, needsNorm);
        }

        public static ResolveResult vendorOnly(Long vId, String vNorm, String pNorm, String reason, boolean needsNorm) {
            return new ResolveResult(false, vId, null, vNorm, pNorm, reason, needsNorm);
        }

        public boolean vendorOnly() {
            return !hit && vendorId != null && productId == null;
        }
    }

    // ============================================================
    // Token matching skip heuristics
    // ============================================================

    private static final Pattern GUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern APPX_PREFIX = Pattern.compile("(?i)^(microsoft\\.|microsoftwindows\\.|windows\\.)");
    private static final Pattern NAMESPACE_DOT = Pattern.compile("(?i)[a-z]\\.[a-z]"); // letter.dot.letter

    /**
     * WindowsのOS/Store/AppX系・GUID系は token matching の誤爆が多いので対象外にする。
     */
    private boolean shouldSkipTokenMatching(String productRaw, String productNorm) {
        String pr = (productRaw == null) ? "" : productRaw.trim();
        if (pr.isEmpty()) return true;

        if (GUID.matcher(pr).matches()) return true;

        String pn = (productNorm == null) ? "" : productNorm.trim();
        if (!pn.isEmpty() && APPX_PREFIX.matcher(pn).find()) return true;

        int hits = 0;
        var m = NAMESPACE_DOT.matcher(pr);
        while (m.find()) {
            hits++;
            if (hits >= 2) return true;
        }

        if (pr.contains(".") && !pr.contains(" ")) return true;

        return false;
    }

    private static Object safeId(SoftwareInstall s) {
        try {
            return s.getId();
        } catch (Exception e) {
            return null;
        }
    }

    private static String safeStr(String s) {
        if (s == null) return "";
        String t = s.trim();
        return (t.length() > 200) ? t.substring(0, 200) + "..." : t;
    }
}