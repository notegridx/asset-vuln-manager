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

    @Transactional(readOnly = true)
    public MappingStats statsOverall(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 5000));
        List<SoftwareInstall> rows = softwareRepo.findAll().stream().limit(safeLimit).toList();
        return stats(rows);
    }

    @Transactional(readOnly = true)
    public Analysis analyze(SoftwareInstall s) {
        boolean linked = (s.getCpeVendorId() != null && s.getCpeProductId() != null);

        ResolveResult r = resolve(s);

        if (linked) {
            boolean vendorOk = vendorRepo.existsById(s.getCpeVendorId());
            boolean prodOk = productRepo.existsById(s.getCpeProductId());

            if (vendorOk && prodOk) {
                return Analysis.linkedOk(r, null);
            }
            String reason = "linked IDs are stale: vendorOk=" + vendorOk + ", productOk=" + prodOk;
            return Analysis.stale(r, reason);
        }

        if (r.hit()) {
            return Analysis.resolved(r, null);
        }

        return Analysis.unresolved(r, r.reason());
    }

    public enum ItemResult {
        LINKED,
        RESOLVED,
        STALE,
        UNRESOLVED
    }

    public record MappingStats(
            int checked,
            int linked,
            int linkedValid,
            int linkedStale,
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

    private static final Pattern GUID = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern APPX_PREFIX = Pattern.compile("(?i)^(microsoft\\.|microsoftwindows\\.|windows\\.)");
    private static final Pattern NAMESPACE_DOT = Pattern.compile("(?i)[a-z]\\.[a-z]");

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