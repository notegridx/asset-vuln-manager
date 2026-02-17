package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    @Transactional(readOnly = true)
    public LinkSummary dryLinkSummary(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 5000));
        List<SoftwareInstall> rows = softwareRepo.findAll().stream().limit(safeLimit).toList();

        int hit = 0;
        int miss = 0;
        int needsNorm = 0;

        for (SoftwareInstall s : rows) {
            var r = resolve(s);
            if (r.needsNormalization()) needsNorm++;
            if (r.hit()) hit++; else miss++;
        }
        return new LinkSummary(rows.size(), hit, miss, needsNorm);
    }

    @Transactional(readOnly = true)
    public ResolveResult resolve(SoftwareInstall s) {
        // 1) ベース正規化（文字種/空白/記号）
        String v0 = normalizer.normalizeVendor(bestEffortVendor(s));
        String p0 = normalizer.normalizeProduct(s.getProduct());

        if (p0 == null) {
            return ResolveResult.miss("product is blank after normalize", true);
        }

        boolean needsNorm = (s.getNormalizedProduct() == null || s.getNormalizedProduct().isBlank());

        // 2) synonym適用(まず vendor -> canonical、次に product -> canonical）
        String v1 = synonymService.canonicalVendorOrSame(v0);
        String p1 = synonymService.canonicalProductOrSame(v1, p0);

        // 3) 辞書参照
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

    public record LinkSummary(int checked, int hit, int miss, int needsNormalization) {}

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
