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
    // Public: stats (vendor-only axis added)
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public MappingStats stats(Collection<SoftwareInstall> rows) {
        int total = 0;

        int vendorLinkedSql = 0;
        int vendorOnlyLinkedSql = 0;
        int fullyLinkedSql = 0;

        int linkedValid = 0;
        int linkedStale = 0;

        int resolvable = 0;
        int unresolvable = 0;

        int needsNorm = 0;

        for (SoftwareInstall s : rows) {
            total++;

            Analysis a = analyze(s);

            if (a.needsNormalization()) needsNorm++;

            if (a.vendorLinkedSql()) vendorLinkedSql++;
            if (a.vendorLinkedSql() && !a.productLinkedSql()) vendorOnlyLinkedSql++;
            if (a.fullyLinkedSql()) fullyLinkedSql++;

            if (a.result() == ItemResult.LINKED) linkedValid++;
            if (a.result() == ItemResult.STALE) linkedStale++;

            if (a.resolvable()) resolvable++;
            if (!a.resolvable()) unresolvable++;
        }

        return new MappingStats(
                total,
                vendorLinkedSql,
                vendorOnlyLinkedSql,
                fullyLinkedSql,
                linkedValid,
                linkedStale,
                resolvable,
                unresolvable,
                needsNorm
        );
    }

    /**
     * Overall stats (first N rows, like the old dryLinkSummary).
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
    //  - vendor-only is expressed by vendorLinkedSql/productLinkedSql flags
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public Analysis analyze(SoftwareInstall s) {

        boolean vendorLinked = (s.getCpeVendorId() != null);
        boolean productLinked = (s.getCpeProductId() != null);
        boolean fullyLinked = vendorLinked && productLinked;

        // Dictionary resolvability from strings (existing behavior)
        ResolveResult r = resolve(s);

        // Fully linked: validate referenced dictionary rows still exist.
        if (fullyLinked) {
            boolean vendorOk = vendorRepo.existsById(s.getCpeVendorId());
            boolean prodOk = productRepo.existsById(s.getCpeProductId());

            if (vendorOk && prodOk) {
                // LINKED (valid). Even if r.hit is false, the record is already linked in DB.
                return Analysis.linkedOk(r, null, vendorLinked, productLinked, fullyLinked);
            }
            // STALE: linked columns exist but dictionary rows missing (or deleted)
            String reason = "linked IDs are stale: vendorOk=" + vendorOk + ", productOk=" + prodOk;
            return Analysis.stale(r, reason, vendorLinked, productLinked, fullyLinked);
        }

        // Not fully linked:
        if (r.hit()) {
            // RESOLVED (resolvable but not yet fully linked in DB)
            return Analysis.resolved(r, null, vendorLinked, productLinked, fullyLinked);
        }

        // UNRESOLVED
        // vendor-only のときは理由を少し補強（UIで見たとき納得感が出る）
        String reason = r.reason();
        if (vendorLinked && !productLinked) {
            reason = (reason == null || reason.isBlank())
                    ? "Vendor is linked, but product is not resolvable from normalized strings."
                    : ("Vendor is linked, but product is not resolvable: " + reason);
        }
        return Analysis.unresolved(r, reason, vendorLinked, productLinked, fullyLinked);
    }

    public enum ItemResult {
        LINKED,      // fully linked and IDs are valid
        RESOLVED,    // not fully linked, but dictionary resolvable from strings
        STALE,       // fully linked, but referenced dictionary rows missing
        UNRESOLVED   // not fully linked and not resolvable
    }

    public record MappingStats(
            int total,

            // SQL link axis
            int vendorLinkedSql,
            int vendorOnlyLinkedSql,
            int fullyLinkedSql,

            // fully linked quality
            int linkedValid,
            int linkedStale,

            // dictionary resolvability
            int resolvable,
            int unresolvable,

            int needsNormalization
    ) {}

    public record Analysis(
            ItemResult result,
            boolean linked, // kept for compatibility (means "fully linked")
            boolean resolvable,
            String reason,
            boolean needsNormalization,
            ResolveResult resolve,

            // SQL link visibility
            boolean vendorLinkedSql,
            boolean productLinkedSql,
            boolean fullyLinkedSql
    ) {
        static Analysis linkedOk(ResolveResult r, String reason,
                                 boolean vendorLinked, boolean productLinked, boolean fullyLinked) {
            return new Analysis(ItemResult.LINKED, true, r.hit(), reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked);
        }

        static Analysis resolved(ResolveResult r, String reason,
                                 boolean vendorLinked, boolean productLinked, boolean fullyLinked) {
            return new Analysis(ItemResult.RESOLVED, false, true, reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked);
        }

        static Analysis stale(ResolveResult r, String reason,
                              boolean vendorLinked, boolean productLinked, boolean fullyLinked) {
            return new Analysis(ItemResult.STALE, true, r.hit(), reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked);
        }

        static Analysis unresolved(ResolveResult r, String reason,
                                   boolean vendorLinked, boolean productLinked, boolean fullyLinked) {
            return new Analysis(ItemResult.UNRESOLVED, false, false, reason, r.needsNormalization(), r,
                    vendorLinked, productLinked, fullyLinked);
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

        // GUID product names
        if (GUID.matcher(pr).matches()) return true;

        // AppX-ish (dot-separated namespace style) by normalized form
        String pn = (productNorm == null) ? "" : productNorm.trim();
        if (!pn.isEmpty() && APPX_PREFIX.matcher(pn).find()) return true;

        // Namespace-ish dot chaining (avoid false positives caused by "14.42.34433" etc.)
        // e.g. "Microsoft.Windows.CloudExperienceHost" => many occurrences of letter.dot.letter
        int hits = 0;
        var m = NAMESPACE_DOT.matcher(pr);
        while (m.find()) {
            hits++;
            if (hits >= 2) return true; // 2回以上ならほぼ namespace
        }

        // Also skip AppX name style: contains dot but no spaces (e.g. Microsoft.AAD.BrokerPlugin / Clipchamp.Clipchamp)
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