package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_AUTOLINK_USE_SYNONYM;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK;

@Slf4j
@Service
public class CanonicalCpeLinkingService {

    private final SoftwareInstallRepository softwareRepo;
    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;
    private final TokenMatchingService tokenMatchingService;
    private final SystemSettingRepository systemSettingRepository;

    public CanonicalCpeLinkingService(
            SoftwareInstallRepository softwareRepo,
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            VendorProductNormalizer normalizer,
            SynonymService synonymService,
            TokenMatchingService tokenMatchingService,
            SystemSettingRepository systemSettingRepository
    ) {
        this.softwareRepo = softwareRepo;
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.normalizer = normalizer;
        this.synonymService = synonymService;
        this.tokenMatchingService = tokenMatchingService;
        this.systemSettingRepository = systemSettingRepository;
    }

    // ------------------------------------------------------------
    // Public: statistics
    // Dictionary buckets are counted only for rows that are not linked
    // at the SQL level (no vendor_id and no product_id).
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public MappingStats stats(Collection<SoftwareInstall> rows) {
        int total = 0;

        // SQL link state
        int vendorOnlyLinkedSql = 0;
        int fullyLinkedSql = 0;
        int notLinkedSql = 0;

        // Quality of fully linked rows
        int linkedValid = 0;
        int linkedStale = 0;

        // Dictionary resolvability for notLinkedSql rows only
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
     * Returns overall mapping statistics for the first N rows.
     */
    @Transactional(readOnly = true)
    public MappingStats statsOverall(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 5000));
        List<SoftwareInstall> rows = softwareRepo.findAll().stream().limit(safeLimit).toList();
        return stats(rows);
    }

    // ------------------------------------------------------------
    // Public: row analysis (LINKED / RESOLVED / STALE / UNRESOLVED)
    //
    // LINKED / STALE:
    //   The row is fully linked at the SQL level
    //   (both vendor_id and product_id are present).
    //
    // RESOLVED:
    //   The row is not fully linked, but dictionary resolution can
    //   fully resolve vendor and product from the current strings.
    //
    // UNRESOLVED:
    //   All other cases.
    //
    // Dictionary buckets (fully resolvable / vendor-only resolvable /
    // unresolvable) are meaningful only when the row is not linked
    // at the SQL level.
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public Analysis analyze(SoftwareInstall s) {

        boolean vendorLinked = (s.getCpeVendorId() != null);
        boolean productLinked = (s.getCpeProductId() != null);

        boolean fullyLinked = vendorLinked && productLinked;
        boolean vendorOnlyLinked = vendorLinked && !productLinked;
        boolean notLinked = !vendorLinked && !productLinked;

        // Resolve current strings against the dictionary using the same
        // logic that the auto-link path uses.
        ResolveResult r = resolve(s);

        // Dictionary buckets are counted only for rows with no SQL link.
        boolean dictFullyResolvable = notLinked && r.hit();
        boolean dictVendorOnlyResolvable = notLinked && r.vendorOnly();
        boolean dictUnresolvable = notLinked && !r.hit() && !r.vendorOnly();

        // Fully linked rows must still be validated against current
        // dictionary contents because referenced IDs may have gone stale.
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

        // Rows that are not fully linked are classified by whether the
        // dictionary can fully resolve them from the current strings.
        if (r.hit()) {
            return Analysis.resolved(r, null,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFullyResolvable, dictVendorOnlyResolvable, dictUnresolvable);
        }

        // For partially linked or not-linked rows, enrich the reason text
        // to make the UI explanation easier to understand.
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
        LINKED,      // Fully linked and referenced IDs are valid
        RESOLVED,    // Not fully linked, but vendor and product are fully resolvable
        STALE,       // Fully linked, but referenced dictionary rows no longer exist
        UNRESOLVED   // Any other case
    }

    public record MappingStats(
            int total,

            // SQL link state
            int fullyLinkedSql,
            int vendorOnlyLinkedSql,
            int notLinkedSql,

            // Quality of fully linked rows
            int linkedValid,
            int linkedStale,

            // Dictionary resolution for notLinkedSql rows only
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

            // Dictionary buckets; meaningful only when notLinkedSql=true
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
    // Resolve (string -> dictionary lookup)
    // - Exact vendor/product lookup
    // - Optional synonym-based canonicalization
    // - Optional token-matching fallback within the resolved vendor
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public ResolveResult resolve(SoftwareInstall s) {
        String v0 = normalizer.normalizeVendor(bestEffortVendor(s));
        String p0 = normalizer.normalizeProduct(s.getProduct());

        boolean needsNorm = (s.getNormalizedProduct() == null || s.getNormalizedProduct().isBlank());

        if (getBool(KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW, true) && s.isCanonicalLinkDisabled()) {
            return ResolveResult.miss("canonical link is disabled for this row", needsNorm, null, v0, p0);
        }

        if (p0 == null) {
            return ResolveResult.miss("product is blank after normalize", needsNorm, null, null, null);
        }

        boolean useSynonym = getBool(KEY_CANONICAL_AUTOLINK_USE_SYNONYM, true);
        boolean useTokenFallback = getBool(KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK, true);

        // Apply optional synonym resolution before dictionary lookup.
        String v1 = useSynonym ? synonymService.canonicalVendorOrSame(v0) : v0;
        String p1 = useSynonym ? synonymService.canonicalProductOrSame(v1, p0) : p0;

        if (v1 == null || v1.isBlank()) {
            return ResolveResult.miss("vendor missing (cannot lookup cpe_products)", needsNorm, null, null, p1);
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return ResolveResult.miss("vendor not found in cpe_vendors: " + v1, needsNorm, null, v1, p1);
        }

        Long vendorId = vendor.getId();

        // Prefer exact product lookup within the resolved vendor.
        CpeProduct prod = productRepo.findByVendorIdAndNameNorm(vendorId, p1).orElse(null);
        if (prod != null) {
            return ResolveResult.hit(vendorId, prod.getId(), v1, p1, needsNorm);
        }

        if (!useTokenFallback) {
            return ResolveResult.vendorOnly(
                    vendorId, v1, p1,
                    "product not found (token fallback disabled): " + v1 + ":" + p1,
                    needsNorm
            );
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

        // Token matching is vendor-scoped and used only as a controlled fallback.
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
    // Token-matching skip heuristics
    // ============================================================

    private static final Pattern GUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern APPX_PREFIX = Pattern.compile("(?i)^(microsoft\\.|microsoftwindows\\.|windows\\.)");
    private static final Pattern NAMESPACE_DOT = Pattern.compile("(?i)[a-z]\\.[a-z]"); // letter.dot.letter

    /**
     * Skips token matching for GUID-like values and Windows / Store / AppX-style
     * identifiers because they often produce noisy or misleading matches.
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

    private boolean getBool(String key, boolean defaultValue) {
        return systemSettingRepository.findById(key)
                .map(s -> s.getSettingValue())
                .map(v -> "true".equalsIgnoreCase(v))
                .orElse(defaultValue);
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