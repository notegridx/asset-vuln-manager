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

/**
 * Resolves installed software rows to canonical CPE vendor/product IDs.
 *
 * <p>This service defines the lookup policy used by both UI analysis and
 * auto-link workflows. The order is intentional:
 *
 * <ol>
 *   <li>normalize current vendor/product strings,</li>
 *   <li>optionally canonicalize them through synonym aliases,</li>
 *   <li>attempt exact dictionary lookup,</li>
 *   <li>optionally fall back to vendor-scoped token matching.</li>
 * </ol>
 *
 * <p>Keeping all paths on the same resolution policy makes mapping results
 * predictable across manual review, bulk backfill, and future imports.
 */
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
    // NOTE: Dictionary buckets are counted only for rows with no SQL link.
    // Once a row already carries a vendor_id and/or product_id, the UI should
    // show link quality rather than treat it as a fresh dictionary candidate.
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
     * Returns aggregate mapping statistics for a bounded sample of rows.
     *
     * <p>The limit is capped to keep this UI-oriented summary predictable even
     * when the inventory grows large.
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
    //   The row is not fully linked, but current strings still resolve
    //   cleanly through the dictionary policy.
    //
    // UNRESOLVED:
    //   All other cases.
    //
    // NOTE: Dictionary buckets are meaningful only when the row has no SQL link.
    // Partially linked rows are shown as operational cleanup cases instead.
    // ------------------------------------------------------------

    /**
     * Classifies one software row from both perspectives:
     * SQL link state and current dictionary resolvability.
     *
     * <p>This split lets the UI distinguish between rows that are already linked,
     * rows that could be auto-linked now, and rows whose stored link has gone stale.
     */
    @Transactional(readOnly = true)
    public Analysis analyze(SoftwareInstall s) {

        boolean vendorLinked = (s.getCpeVendorId() != null);
        boolean productLinked = (s.getCpeProductId() != null);

        boolean fullyLinked = vendorLinked && productLinked;
        boolean vendorOnlyLinked = vendorLinked && !productLinked;
        boolean notLinked = !vendorLinked && !productLinked;

        // Reuse the same resolver as auto-link so review screens and write paths
        // explain the same outcome for the same input strings.
        ResolveResult r = resolve(s);

        // These buckets intentionally exclude partially linked rows because the
        // operational question there is cleanup, not first-time resolvability.
        boolean dictFullyResolvable = notLinked && r.hit();
        boolean dictVendorOnlyResolvable = notLinked && r.vendorOnly();
        boolean dictUnresolvable = notLinked && !r.hit() && !r.vendorOnly();

        // Stored IDs can become invalid after dictionary refresh or cleanup, so
        // a row that looks linked in SQL still needs dictionary existence checks.
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

        // Rows without a full SQL link are treated as resolved only when the
        // current lookup policy can reach both canonical IDs deterministically.
        if (r.hit()) {
            return Analysis.resolved(r, null,
                    vendorLinked, productLinked, fullyLinked, vendorOnlyLinked, notLinked,
                    dictFullyResolvable, dictVendorOnlyResolvable, dictUnresolvable);
        }

        // Expand the explanation for common cleanup states so the UI can show
        // why the row stopped short of a full canonical link.
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

    /**
     * Resolves one software row to canonical dictionary IDs.
     *
     * <p>The resolution flow is deliberately strict before it becomes fuzzy:
     * normalized lookup first, synonym canonicalization second, token fallback
     * last. This keeps exact matches deterministic while still recovering
     * common raw-name variations.
     */
    @Transactional(readOnly = true)
    public ResolveResult resolve(SoftwareInstall s) {
        String v0 = normalizer.normalizeVendor(bestEffortVendor(s));
        String p0 = normalizer.normalizeProduct(s.getProduct());

        boolean needsNorm = (s.getNormalizedProduct() == null || s.getNormalizedProduct().isBlank());

        // Respect explicit row-level opt-out before any automated resolution path.
        if (getBool(KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW, true) && s.isCanonicalLinkDisabled()) {
            return ResolveResult.miss("canonical link is disabled for this row", needsNorm, null, v0, p0);
        }

        if (p0 == null) {
            return ResolveResult.miss("product is blank after normalize", needsNorm, null, null, null);
        }

        boolean useSynonym = getBool(KEY_CANONICAL_AUTOLINK_USE_SYNONYM, true);
        boolean useTokenFallback = getBool(KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK, true);

        // Synonyms run before repository lookup so aliases and display-name drift
        // still converge on the same canonical vendor/product keys.
        String v1 = useSynonym ? synonymService.canonicalVendorOrSame(v0) : v0;
        String p1 = useSynonym ? synonymService.canonicalProductOrSame(v1, p0) : p0;

        // Product lookup is vendor-scoped, so missing vendor means there is no
        // safe product search space yet.
        if (v1 == null || v1.isBlank()) {
            return ResolveResult.miss("vendor missing (cannot lookup cpe_products)", needsNorm, null, null, p1);
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return ResolveResult.miss("vendor not found in cpe_vendors: " + v1, needsNorm, null, v1, p1);
        }

        Long vendorId = vendor.getId();

        // Exact product lookup stays first so token matching never overrides a
        // deterministic dictionary hit.
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

        // NOTE: Token matching is intentionally skipped for identifier-heavy
        // values that tend to create plausible-looking but incorrect matches.
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

        // Token matching is the last recovery path and remains vendor-scoped to
        // avoid cross-vendor drift when short or generic product tokens overlap.
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
     * Skips token matching for identifier-like product names that usually
     * represent platform package IDs rather than human-readable product names.
     *
     * <p>This is a precision guardrail. Missing one fuzzy match is cheaper than
     * auto-linking a Windows/AppX identifier to the wrong product.
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