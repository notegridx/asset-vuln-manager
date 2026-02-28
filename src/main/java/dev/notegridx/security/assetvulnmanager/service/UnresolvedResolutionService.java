package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.service.VendorProductNormalizer;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class UnresolvedResolutionService {

    private final UnresolvedMappingRepository unresolvedRepo;
    private final SoftwareInstallRepository softwareRepo;
    private final VendorProductNormalizer normalizer;

    public UnresolvedResolutionService(
            UnresolvedMappingRepository unresolvedRepo,
            SoftwareInstallRepository softwareRepo,
            VendorProductNormalizer normalizer
    ) {
        this.unresolvedRepo = unresolvedRepo;
        this.softwareRepo = softwareRepo;
        this.normalizer = normalizer;
    }

    public record ApplyResult(
            Long mappingId,
            Long vendorId,
            Long productId,
            int affectedSoftwareRows,
            String status
    ) {}

    @Transactional
    public ApplyResult apply(Long mappingId, Long vendorId, Long productId) {
        UnresolvedMapping um = unresolvedRepo.findById(mappingId).orElseThrow();

        // 1) 正規化値が入ってなければ補完（保険）
        String vendorNorm = normalizeVendorFallback(um);
        String productNorm = normalizeProductFallback(um);

        if (vendorId == null) {
            throw new IllegalArgumentException("vendorId is required");
        }

        int affected;
        String status;

        if (productId == null) {
            // vendor だけ確定
            if (vendorNorm == null || vendorNorm.isBlank()) {
                throw new IllegalStateException("normalizedVendor is missing");
            }
            affected = softwareRepo.bulkSetCpeVendorIdByNormalizedVendor(vendorId, vendorNorm);
            status = "VENDOR_LINKED";
        } else {
            // vendor+product 確定
            if (vendorNorm == null || vendorNorm.isBlank() || productNorm == null || productNorm.isBlank()) {
                throw new IllegalStateException("normalizedVendor/normalizedProduct is missing");
            }
            affected = softwareRepo.bulkSetCpeVendorProductIdByNormalizedVendorProduct(
                    vendorId, productId, vendorNorm, productNorm
            );
            status = "RESOLVED";
        }

        // 2) Unresolved のステータス更新
        um.setStatus(status);
        um.setLastSeenAt(LocalDateTime.now());
        unresolvedRepo.save(um);

        return new ApplyResult(mappingId, vendorId, productId, affected, status);
    }

    private String normalizeVendorFallback(UnresolvedMapping um) {
        if (um.getNormalizedVendor() != null && !um.getNormalizedVendor().isBlank()) {
            return um.getNormalizedVendor();
        }
        String v = um.getVendorRaw();
        if (v == null || v.isBlank()) return null;
        String n = normalizer.normalizeVendor(v);
        um.setNormalizedVendor(n);
        return n;
    }

    private String normalizeProductFallback(UnresolvedMapping um) {
        if (um.getNormalizedProduct() != null && !um.getNormalizedProduct().isBlank()) {
            return um.getNormalizedProduct();
        }
        String p = um.getProductRaw();
        if (p == null || p.isBlank()) return null;
        String n = normalizer.normalizeProduct(p);
        um.setNormalizedProduct(n);
        return n;
    }
}