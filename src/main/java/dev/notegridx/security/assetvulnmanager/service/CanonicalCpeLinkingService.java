package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;

@Service
public class CanonicalCpeLinkingService {

    private final SoftwareInstallRepository softwareRepo;
    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final VendorProductNormalizer normalizer;
    private final SynonymService synonymService;

    public CanonicalCpeLinkingService(
            SoftwareInstallRepository softwareRepo,
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            VendorProductNormalizer normalizer,
            SynonymService synonymService
    ) {
        this.softwareRepo = softwareRepo;
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.normalizer = normalizer;
        this.synonymService = synonymService;
    }

    // ------------------------------------------------------------
    // Public: stats (linked vs resolvable separated)
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public MappingStats stats(Collection<SoftwareInstall> rows) {
        int checked = 0;

        int linked = 0;
        int linkedValid = 0;
        int linkedStale = 0;

        int resolvable = 0;
        int unresolvable = 0;

        int needsNorm = 0;

        for (SoftwareInstall s : rows) {
            checked++;

            Analysis a = analyze(s);

            if (a.needsNormalization()) needsNorm++;

            if (a.linked()) linked++;
            if (a.result() == ItemResult.LINKED) linkedValid++;
            if (a.result() == ItemResult.STALE) linkedStale++;

            if (a.resolvable()) resolvable++;
            if (!a.resolvable()) unresolvable++;
        }

        return new MappingStats(
                checked,
                linked, linkedValid, linkedStale,
                resolvable, unresolvable,
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
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public Analysis analyze(SoftwareInstall s) {
        boolean linked = (s.getCpeVendorId() != null && s.getCpeProductId() != null);

        // Dictionary resolvability from strings (existing behavior)
        ResolveResult r = resolve(s);

        // If linked, validate whether the referenced IDs still exist.
        if (linked) {
            boolean vendorOk = vendorRepo.existsById(s.getCpeVendorId());
            boolean prodOk = productRepo.existsById(s.getCpeProductId());

            if (vendorOk && prodOk) {
                // LINKED (valid). Even if r.hit is false, the record is already linked in DB.
                return Analysis.linkedOk(r, null);
            }
            // STALE: linked columns exist but dictionary rows missing (or deleted)
            String reason = "linked IDs are stale: vendorOk=" + vendorOk + ", productOk=" + prodOk;
            return Analysis.stale(r, reason);
        }

        // Not linked:
        if (r.hit()) {
            // RESOLVED (resolvable but not yet linked in DB)
            return Analysis.resolved(r, null);
        }

        // UNRESOLVED
        return Analysis.unresolved(r, r.reason());
    }

    public enum ItemResult {
        LINKED,      // DB link exists and valid
        RESOLVED,    // not linked, but dictionary resolvable from strings
        STALE,       // DB link exists, but referenced dictionary rows missing
        UNRESOLVED   // not linked and not resolvable
    }

    public record MappingStats(
            int checked,

            // SQL-level link status
            int linked,
            int linkedValid,
            int linkedStale,

            // dictionary resolvability
            int resolvable,
            int unresolvable,

            int needsNormalization
    ) {}

    public record Analysis(
            ItemResult result,
            boolean linked,
            boolean resolvable,
            String reason,
            boolean needsNormalization,
            ResolveResult resolve
    ) {
        static Analysis linkedOk(ResolveResult r, String reason) {
            return new Analysis(ItemResult.LINKED, true, r.hit(), reason, r.needsNormalization(), r);
        }
        static Analysis resolved(ResolveResult r, String reason) {
            return new Analysis(ItemResult.RESOLVED, false, true, reason, r.needsNormalization(), r);
        }
        static Analysis stale(ResolveResult r, String reason) {
            return new Analysis(ItemResult.STALE, true, r.hit(), reason, r.needsNormalization(), r);
        }
        static Analysis unresolved(ResolveResult r, String reason) {
            return new Analysis(ItemResult.UNRESOLVED, false, false, reason, r.needsNormalization(), r);
        }
    }

    // ------------------------------------------------------------
    // Existing: resolve (string -> dictionary lookup)
    // ------------------------------------------------------------

    @Transactional(readOnly = true)
    public ResolveResult resolve(SoftwareInstall s) {
        // 1) base normalize
        String v0 = normalizer.normalizeVendor(bestEffortVendor(s));
        String p0 = normalizer.normalizeProduct(s.getProduct());

        if (p0 == null) {
            return ResolveResult.miss("product is blank after normalize", true);
        }

        boolean needsNorm = (s.getNormalizedProduct() == null || s.getNormalizedProduct().isBlank());

        // 2) apply synonym (vendor then product)
        String v1 = synonymService.canonicalVendorOrSame(v0);
        String p1 = synonymService.canonicalProductOrSame(v1, p0);

        // 3) dictionary lookup
        if (v1 == null || v1.isBlank()) {
            return ResolveResult.miss("vendor missing (cannot lookup cpe_products)", needsNorm);
        }

        CpeVendor vendor = vendorRepo.findByNameNorm(v1).orElse(null);
        if (vendor == null) {
            return ResolveResult.miss("vendor not found in cpe_vendors: " + v1, needsNorm);
        }

        CpeProduct prod = productRepo.findByVendorIdAndNameNorm(vendor.getId(), p1).orElse(null);
        if (prod == null) {
            return ResolveResult.miss("product not found in cpe_products: " + v1 + ":" + p1, needsNorm);
        }

        return ResolveResult.hit(vendor.getId(), prod.getId(), v1, p1, needsNorm);
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

        public static ResolveResult miss(String reason, boolean needsNorm) {
            return new ResolveResult(false, null, null, null, null, reason, needsNorm);
        }
    }
}