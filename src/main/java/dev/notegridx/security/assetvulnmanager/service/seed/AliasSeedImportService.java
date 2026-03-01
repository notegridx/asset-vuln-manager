package dev.notegridx.security.assetvulnmanager.service.seed;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.service.VendorProductNormalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class AliasSeedImportService {

    private static final Logger log = LoggerFactory.getLogger(AliasSeedImportService.class);

    private static final String ACTIVE = "ACTIVE";
    private static final int DEFAULT_CONFIDENCE = 95; // seed default (0..100)

    private final ObjectMapper objectMapper;
    private final VendorProductNormalizer normalizer;

    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;
    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;

    public AliasSeedImportService(
            ObjectMapper objectMapper,
            VendorProductNormalizer normalizer,
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo,
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo
    ) {
        this.objectMapper = objectMapper;
        this.normalizer = normalizer;
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
    }

    public record SeedReport(
            int vendorInserted,
            int vendorSkippedExisting,
            int vendorConflicted,
            int vendorCanonicalNotFound,

            int productInserted,
            int productSkippedExisting,
            int productConflicted,
            int productCanonicalNotFound,

            int dedupedAliases,
            List<String> notes
    ) {}

    @Transactional
    public SeedReport importFromJson(String jsonText) {
        try {
            AliasSeedPayload payload = objectMapper.readValue(jsonText, AliasSeedPayload.class);
            return importPayload(payload);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid seed JSON: " + e.getMessage(), e);
        }
    }

    @Transactional
    public SeedReport importPayload(AliasSeedPayload payload) {
        if (payload == null) throw new IllegalArgumentException("payload is null");
        if (payload.getVersion() != 1) throw new IllegalArgumentException("Unsupported seed version: " + payload.getVersion());

        String batchTag = (payload.getSource() == null || payload.getSource().isBlank()) ? "seed" : payload.getSource();

        int vIns = 0, vSkip = 0, vConflict = 0, vMissing = 0;
        int pIns = 0, pSkip = 0, pConflict = 0, pMissing = 0;
        int deduped = 0;

        List<String> notes = new ArrayList<>();

        // ---------------- VENDOR ----------------
        for (AliasSeedPayload.VendorSeed seed : safeList(payload.getVendors())) {

            String canonicalVendorNorm = normalizer.normalizeVendor(seed.getCanonicalVendor());
            if (canonicalVendorNorm == null) {
                vMissing++;
                notes.add("vendor canonical blank: " + seed.getCanonicalVendor());
                continue;
            }

            Optional<CpeVendor> canonicalVendor = vendorRepo.findByNameNorm(canonicalVendorNorm);
            if (canonicalVendor.isEmpty()) {
                vMissing++;
                notes.add("vendor canonical not found in cpe_vendors.name_norm: " + canonicalVendorNorm);
                continue;
            }

            Long vendorId = canonicalVendor.get().getId();
            Set<String> seen = new HashSet<>();

            for (AliasSeedPayload.AliasItem item : safeList(seed.getAliases())) {

                String aliasNorm = normalizer.normalizeVendor(item.getRaw());
                if (aliasNorm == null) continue;

                if (!seen.add(aliasNorm)) {
                    deduped++;
                    continue;
                }

                Optional<CpeVendorAlias> existing =
                        vendorAliasRepo.findFirstByAliasNormAndStatusIgnoreCase(aliasNorm, ACTIVE);

                if (existing.isPresent()) {
                    if (Objects.equals(existing.get().getCpeVendorId(), vendorId)) {
                        vSkip++;
                    } else {
                        vConflict++;
                        notes.add("VENDOR CONFLICT alias_norm='" + aliasNorm
                                + "' existingVendorId=" + existing.get().getCpeVendorId()
                                + " wantedVendorId=" + vendorId);
                    }
                    continue;
                }

                int confidence = sanitizeConfidence(item.getConfidence());
                String evidence = (item.getEvidenceUrl() == null || item.getEvidenceUrl().isBlank())
                        ? null
                        : item.getEvidenceUrl();

                String note = batchTag;

                // ✅ VENDOR: CpeVendorAlias / vendorAliasRepo
                CpeVendorAlias entity = CpeVendorAlias.seeded(
                        vendorId,
                        aliasNorm,
                        note,
                        AliasSource.SEED,
                        AliasReviewState.AUTO,
                        confidence,
                        evidence
                );

                vendorAliasRepo.save(entity);
                vIns++;
            }
        }

        // ---------------- PRODUCT ----------------
        for (AliasSeedPayload.ProductSeed seed : safeList(payload.getProducts())) {

            String canonicalVendorNorm = normalizer.normalizeVendor(seed.getCanonicalVendor());
            String canonicalProductNorm = normalizer.normalizeProduct(seed.getCanonicalProduct());

            if (canonicalVendorNorm == null || canonicalProductNorm == null) {
                pMissing++;
                notes.add("product canonical blank: vendor=" + seed.getCanonicalVendor()
                        + " product=" + seed.getCanonicalProduct());
                continue;
            }

            Optional<CpeVendor> canonicalVendor = vendorRepo.findByNameNorm(canonicalVendorNorm);
            if (canonicalVendor.isEmpty()) {
                pMissing++;
                notes.add("product canonical vendor not found: " + canonicalVendorNorm);
                continue;
            }
            Long vendorId = canonicalVendor.get().getId();

            Optional<CpeProduct> canonicalProduct =
                    productRepo.findByVendorIdAndNameNorm(vendorId, canonicalProductNorm);

            if (canonicalProduct.isEmpty()) {
                pMissing++;
                notes.add("product canonical not found: vendor=" + canonicalVendorNorm
                        + " product=" + canonicalProductNorm);
                continue;
            }
            Long productId = canonicalProduct.get().getId();

            Set<String> seen = new HashSet<>();

            for (AliasSeedPayload.AliasItem item : safeList(seed.getAliases())) {

                String aliasNorm = normalizer.normalizeProduct(item.getRaw());
                if (aliasNorm == null) continue;

                if (!seen.add(aliasNorm)) {
                    deduped++;
                    continue;
                }

                Optional<CpeProductAlias> existing =
                        productAliasRepo.findFirstByCpeVendorIdAndAliasNormAndStatusIgnoreCase(vendorId, aliasNorm, ACTIVE);

                if (existing.isPresent()) {
                    if (Objects.equals(existing.get().getCpeProductId(), productId)) {
                        pSkip++;
                    } else {
                        pConflict++;
                        notes.add("PRODUCT CONFLICT vendorId=" + vendorId
                                + " alias_norm='" + aliasNorm
                                + "' existingProductId=" + existing.get().getCpeProductId()
                                + " wantedProductId=" + productId);
                    }
                    continue;
                }

                int confidence = sanitizeConfidence(item.getConfidence());
                String evidence = (item.getEvidenceUrl() == null || item.getEvidenceUrl().isBlank())
                        ? null
                        : item.getEvidenceUrl();

                String note = batchTag;

                // ✅ PRODUCT: CpeProductAlias / productAliasRepo / seeded is 8-args
                CpeProductAlias entity = CpeProductAlias.seeded(
                        vendorId,
                        productId,
                        aliasNorm,
                        note,
                        AliasSource.SEED,
                        AliasReviewState.AUTO,
                        confidence,
                        evidence
                );

                productAliasRepo.save(entity);
                pIns++;
            }
        }

        log.info("Alias seed import done: vIns={} vSkip={} vConflict={} vMissing={} | pIns={} pSkip={} pConflict={} pMissing={} | deduped={}",
                vIns, vSkip, vConflict, vMissing, pIns, pSkip, pConflict, pMissing, deduped);

        return new SeedReport(
                vIns, vSkip, vConflict, vMissing,
                pIns, pSkip, pConflict, pMissing,
                deduped,
                notes
        );
    }

    private static int sanitizeConfidence(Integer c) {
        int v = (c == null) ? DEFAULT_CONFIDENCE : c;
        if (v < 0) v = 0;
        if (v > 100) v = 100;
        return v;
    }

    private static <T> List<T> safeList(List<T> v) {
        return (v == null) ? List.of() : v;
    }
}