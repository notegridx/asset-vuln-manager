package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UnresolvedQuickAddService {

    public enum AliasOutcome {
        INSERTED,
        UPDATED,
        SKIPPED_ALREADY_SAME,
        SKIPPED_CONFLICT,
        SKIPPED_EMPTY_ALIAS,
        NOT_REQUESTED
    }

    public record QuickAddResult(
            AliasOutcome vendorAliasOutcome,
            AliasOutcome productAliasOutcome,
            UnresolvedResolutionService.ApplyResult apply
    ) {}

    private final UnresolvedMappingRepository unresolvedRepo;
    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final UnresolvedResolutionService unresolvedResolutionService;
    private final SynonymService synonymService;

    public UnresolvedQuickAddService(
            UnresolvedMappingRepository unresolvedRepo,
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            UnresolvedResolutionService unresolvedResolutionService,
            SynonymService synonymService
    ) {
        this.unresolvedRepo = unresolvedRepo;
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.unresolvedResolutionService = unresolvedResolutionService;
        this.synonymService = synonymService;
    }

    @Transactional
    public QuickAddResult quickAddAndApply(Long mappingId, Long vendorId, Long productId) {
        if (mappingId == null) throw new IllegalArgumentException("mappingId is required");
        if (vendorId == null) throw new IllegalArgumentException("vendorId is required");

        UnresolvedMapping um = unresolvedRepo.findById(mappingId).orElseThrow();

        String vendorAliasNorm = trimOrEmpty(um.getNormalizedVendor());
        String productAliasNorm = trimOrEmpty(um.getNormalizedProduct());

        AliasOutcome vOut = upsertVendorAlias(vendorAliasNorm, vendorId, mappingId);
        AliasOutcome pOut = AliasOutcome.NOT_REQUESTED;

        if (productId != null) {
            pOut = upsertProductAlias(productAliasNorm, vendorId, productId, mappingId);
        }

        // Immediately apply alias changes by clearing synonym caches
        synonymService.clearCaches();

        // Reuse existing apply logic as-is
        var apply = unresolvedResolutionService.apply(mappingId, vendorId, productId);

        return new QuickAddResult(vOut, pOut, apply);
    }

    private AliasOutcome upsertVendorAlias(String aliasNorm, Long vendorId, Long mappingId) {
        if (aliasNorm.isEmpty()) return AliasOutcome.SKIPPED_EMPTY_ALIAS;

        var existingOpt = vendorAliasRepo.findByAliasNorm(aliasNorm);

        if (existingOpt.isEmpty()) {
            // Use seeded factory to register alias as a suggested entry
            CpeVendorAlias a = CpeVendorAlias.seeded(
                    vendorId,
                    aliasNorm,
                    "from unresolved#" + mappingId,
                    AliasSource.MANUAL,       // Replace if a dedicated UNRESOLVED enum is introduced
                    AliasReviewState.AUTO,    // Replace if a dedicated SUGGEST enum is introduced
                    80,
                    null
            );
            vendorAliasRepo.save(a);
            return AliasOutcome.INSERTED;
        }

        CpeVendorAlias existing = existingOpt.get();

        // UNIQUE(alias_norm): prevent overwriting if already linked to a different vendor
        if (existing.getCpeVendorId() != null && !existing.getCpeVendorId().equals(vendorId)) {
            return AliasOutcome.SKIPPED_CONFLICT;
        }

        boolean changed = false;

        if (!CpeVendorAlias.STATUS_ACTIVE.equalsIgnoreCase(existing.getStatus())) {
            existing.setStatus(CpeVendorAlias.STATUS_ACTIVE);
            changed = true;
        }

        // If the alias already belongs to the same vendor, metadata updates can be enabled here if needed
        // existing.setReviewState(AliasReviewState.AUTO);
        // existing.setConfidence(Math.max(existing.getConfidence() == null ? 0 : existing.getConfidence(), 80));

        if (changed) {
            vendorAliasRepo.save(existing);
            return AliasOutcome.UPDATED;
        }
        return AliasOutcome.SKIPPED_ALREADY_SAME;
    }

    private AliasOutcome upsertProductAlias(String aliasNorm, Long vendorId, Long productId, Long mappingId) {
        if (aliasNorm.isEmpty()) return AliasOutcome.SKIPPED_EMPTY_ALIAS;

        var existingOpt = productAliasRepo.findByCpeVendorIdAndAliasNorm(vendorId, aliasNorm);

        if (existingOpt.isEmpty()) {
            CpeProductAlias a = CpeProductAlias.seeded(
                    vendorId,
                    productId,
                    aliasNorm,
                    "from unresolved#" + mappingId,
                    AliasSource.MANUAL,       // Replace if a dedicated UNRESOLVED enum is introduced
                    AliasReviewState.AUTO,    // Replace if a dedicated SUGGEST enum is introduced
                    80,
                    null
            );
            productAliasRepo.save(a);
            return AliasOutcome.INSERTED;
        }

        CpeProductAlias existing = existingOpt.get();

        // UNIQUE(cpe_vendor_id, alias_norm): prevent overwriting if already linked to a different product
        if (existing.getCpeProductId() != null && !existing.getCpeProductId().equals(productId)) {
            return AliasOutcome.SKIPPED_CONFLICT;
        }

        boolean changed = false;

        if (!CpeProductAlias.STATUS_ACTIVE.equalsIgnoreCase(existing.getStatus())) {
            existing.setStatus(CpeProductAlias.STATUS_ACTIVE);
            changed = true;
        }

        if (changed) {
            productAliasRepo.save(existing);
            return AliasOutcome.UPDATED;
        }
        return AliasOutcome.SKIPPED_ALREADY_SAME;
    }

    private static String trimOrEmpty(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.isEmpty() ? "" : t;
    }
}