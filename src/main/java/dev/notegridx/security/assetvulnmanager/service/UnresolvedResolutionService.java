package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UnresolvedResolutionService {

    private final UnresolvedMappingRepository unresolvedRepo;
    private final SoftwareInstallRepository softwareRepo;
    private final VendorProductNormalizer normalizer;

    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    public UnresolvedResolutionService(
            UnresolvedMappingRepository unresolvedRepo,
            SoftwareInstallRepository softwareRepo,
            VendorProductNormalizer normalizer,
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository
    ) {
        this.unresolvedRepo = unresolvedRepo;
        this.softwareRepo = softwareRepo;
        this.normalizer = normalizer;
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
    }

    public record ApplyResult(
            Long mappingId,
            Long vendorId,
            Long productId,
            int affectedSoftwareRows,
            String status,
            String vendorAliasOutcome,
            String productAliasOutcome
    ) {}

    @Transactional
    public ApplyResult apply(Long mappingId, Long vendorId, Long productId) {
        if (mappingId == null) throw new IllegalArgumentException("mappingId is required");
        if (vendorId == null) throw new IllegalArgumentException("vendorId is required");

        UnresolvedMapping um = unresolvedRepo.findById(mappingId).orElseThrow();

        // Raw values (used for coalesce-match fallback and alias note)
        String vendorRaw = safeTrim(um.getVendorRaw());
        String productRaw = safeTrim(um.getProductRaw());

        // Normalized values (primary update path; fallback fill for UnresolvedMapping only)
        String vendorNorm = normalizeVendorFallback(um);
        String productNorm = normalizeProductFallback(um);

        int affected = 0;
        String status;

        if (productId == null) {
            // =========================
            // Vendor only
            // =========================
            if (!isBlank(vendorNorm)) {
                affected = softwareRepo.bulkSetCpeVendorIdByNormalizedVendor(vendorId, vendorNorm);
            }
            if (affected == 0 && !isBlank(vendorRaw)) {
                affected = softwareRepo.bulkSetCpeVendorIdByVendorRawCoalesce(vendorId, vendorRaw);
            }
            status = "VENDOR_LINKED";

        } else {
            // =========================
            // Vendor + Product
            // =========================
            if (!isBlank(vendorNorm) && !isBlank(productNorm)) {
                affected = softwareRepo.bulkSetCpeVendorProductIdByNormalizedVendorProduct(
                        vendorId, productId, vendorNorm, productNorm
                );
            }
            if (affected == 0 && !isBlank(vendorRaw) && !isBlank(productRaw)) {
                affected = softwareRepo.bulkSetCpeVendorProductIdByVendorProductRawCoalesce(
                        vendorId, productId, vendorRaw, productRaw
                );
            }
            status = "RESOLVED";
        }

        // =========================
        // Learn (alias upsert)
        // =========================
        String vendorAliasOutcome = learnVendorAlias(vendorId, vendorRaw, vendorNorm, mappingId);
        String productAliasOutcome = (productId == null)
                ? "(skipped)"
                : learnProductAlias(vendorId, productId, productRaw, productNorm, mappingId);

        // =========================
        // Resolve linked canonical names for display persistence
        // =========================
        CpeVendor vendor = cpeVendorRepository.findById(vendorId).orElseThrow();
        CpeProduct product = (productId == null)
                ? null
                : cpeProductRepository.findById(productId).orElseThrow();

        // =========================
        // Update unresolved queue state
        // =========================
        um.setLinkedCpeVendorId(vendorId);
        um.setLinkedCpeProductId(productId);
        um.setLinkedVendorName(firstNonBlank(vendor.getDisplayName(), vendor.getNameNorm()));
        um.setLinkedProductName(product != null
                ? firstNonBlank(product.getDisplayName(), product.getNameNorm())
                : null);

        um.setStatus(status);
        um.setLastSeenAt(DbTime.now());
        unresolvedRepo.save(um);

        return new ApplyResult(mappingId, vendorId, productId, affected, status, vendorAliasOutcome, productAliasOutcome);
    }

    // ---------------------------------------------------------
    // Learning: Vendor alias
    // ---------------------------------------------------------
    private String learnVendorAlias(Long vendorId, String vendorRaw, String vendorNorm, Long mappingId) {
        String aliasNorm = firstNonBlank(vendorNorm, normalizeVendorFromRaw(vendorRaw));
        if (isBlank(aliasNorm)) return "(skipped: vendor alias blank)";

        var existing = vendorAliasRepo.findByAliasNorm(aliasNorm).orElse(null);
        String note = buildNote("applied-from-unresolved", mappingId, vendorRaw, null);

        if (existing == null) {
            // Entity has constructor (aliasNorm, cpeVendorId, note)
            CpeVendorAlias created = new CpeVendorAlias(aliasNorm, vendorId, note);
            // Apply action is treated as MANUAL decision
            created.setSource(AliasSource.MANUAL);
            created.setReviewState(AliasReviewState.MANUAL);
            created.setStatus(CpeVendorAlias.STATUS_ACTIVE);
            vendorAliasRepo.save(created);
            return "CREATED";
        }

        // Cannot change cpeVendorId / aliasNorm (no setters available) → only safe updates allowed
        if (!existing.getCpeVendorId().equals(vendorId)) {
            // Conflict: aliasNorm already points to a different vendor
            return "CONFLICT(existingVendorId=" + existing.getCpeVendorId() + ")";
        }

        boolean changed = false;

        if (existing.getStatus() == null || !existing.getStatus().equalsIgnoreCase(CpeVendorAlias.STATUS_ACTIVE)) {
            existing.setStatus(CpeVendorAlias.STATUS_ACTIVE);
            changed = true;
        }
        if (isBlank(existing.getNote()) && !isBlank(note)) {
            existing.setNote(note);
            changed = true;
        }

        if (changed) {
            vendorAliasRepo.save(existing);
            return "UPDATED";
        }
        return "UNCHANGED";
    }

    // ---------------------------------------------------------
    // Learning: Product alias (vendor-scoped)
    // ---------------------------------------------------------

    private String learnProductAlias(Long vendorId, Long productId, String productRaw, String productNorm, Long mappingId) {
        String aliasNorm = firstNonBlank(productNorm, normalizeProductFromRaw(productRaw));
        if (isBlank(aliasNorm)) return "(skipped: product alias blank)";

        var existing = productAliasRepo.findByCpeVendorIdAndAliasNorm(vendorId, aliasNorm).orElse(null);
        String note = buildNote("applied-from-unresolved", mappingId, null, productRaw);

        if (existing == null) {
            CpeProductAlias created = new CpeProductAlias(vendorId, productId, aliasNorm, note);
            created.setSource(AliasSource.MANUAL);
            created.setReviewState(AliasReviewState.MANUAL);
            created.setStatus(CpeProductAlias.STATUS_ACTIVE);

            // Required if DB column is NOT NULL
            created.setConfidence(0);

            productAliasRepo.save(created);
            return "CREATED";
        }

        if (!existing.getCpeProductId().equals(productId)) {
            return "CONFLICT(existingProductId=" + existing.getCpeProductId() + ")";
        }

        boolean changed = false;

        if (existing.getStatus() == null || !existing.getStatus().equalsIgnoreCase(CpeProductAlias.STATUS_ACTIVE)) {
            existing.setStatus(CpeProductAlias.STATUS_ACTIVE);
            changed = true;
        }
        if (isBlank(existing.getNote()) && !isBlank(note)) {
            existing.setNote(note);
            changed = true;
        }

        // Recover cases where confidence is unexpectedly null (e.g., schema mismatch during migration)
        if (existing.getConfidence() == null) {
            existing.setConfidence(0);
            changed = true;
        }

        if (changed) {
            productAliasRepo.save(existing);
            return "UPDATED";
        }
        return "UNCHANGED";
    }

    // ---------------------------------------------------------
    // UnresolvedMapping normalization fallback (insurance)
    // ---------------------------------------------------------
    private String normalizeVendorFallback(UnresolvedMapping um) {
        if (!isBlank(um.getNormalizedVendor())) return um.getNormalizedVendor();
        String v = um.getVendorRaw();
        if (isBlank(v)) return null;
        String n = normalizer.normalizeVendor(v);
        um.setNormalizedVendor(n);
        return n;
    }

    private String normalizeProductFallback(UnresolvedMapping um) {
        if (!isBlank(um.getNormalizedProduct())) return um.getNormalizedProduct();
        String p = um.getProductRaw();
        if (isBlank(p)) return null;
        String n = normalizer.normalizeProduct(p);
        um.setNormalizedProduct(n);
        return n;
    }

    private String normalizeVendorFromRaw(String raw) {
        if (isBlank(raw)) return null;
        return normalizer.normalizeVendor(raw);
    }

    private String normalizeProductFromRaw(String raw) {
        if (isBlank(raw)) return null;
        return normalizer.normalizeProduct(raw);
    }

    private static String buildNote(String prefix, Long mappingId, String vendorRaw, String productRaw) {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);
        if (mappingId != null) sb.append(" mappingId=").append(mappingId);
        if (!isBlank(vendorRaw)) sb.append(" vendorRaw=").append(vendorRaw.trim());
        if (!isBlank(productRaw)) sb.append(" productRaw=").append(productRaw.trim());
        return sb.toString();
    }

    // ---------------------------------------------------------
    // helpers
    // ---------------------------------------------------------
    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String safeTrim(String s) {
        return s == null ? null : s.trim();
    }

    private static String firstNonBlank(String a, String b) {
        if (!isBlank(a)) return a.trim();
        if (!isBlank(b)) return b.trim();
        return null;
    }
}