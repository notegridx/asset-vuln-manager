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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Service
public class AliasSeedImportService {

    private static final Logger log = LoggerFactory.getLogger(AliasSeedImportService.class);

    private static final String ACTIVE = "ACTIVE";
    private static final int DEFAULT_CONFIDENCE = 95;

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
            List<String> notes,
            ImportDetails details
    ) {
    }

    public record ImportDetails(
            List<ResultRow> vendorInsertedRows,
            List<ResultRow> vendorSkippedExistingRows,
            List<ResultRow> vendorConflictedRows,
            List<ResultRow> vendorCanonicalNotFoundRows,
            List<ResultRow> productInsertedRows,
            List<ResultRow> productSkippedExistingRows,
            List<ResultRow> productConflictedRows,
            List<ResultRow> productCanonicalNotFoundRows,
            List<ResultRow> dedupedAliasRows
    ) {
    }

    public record ResultRow(
            String type,
            String canonical,
            String aliasNorm,
            String raw,
            String detail
    ) {
    }

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
        if (payload == null) {
            throw new IllegalArgumentException("payload is null");
        }
        if (payload.getVersion() != 1) {
            throw new IllegalArgumentException("Unsupported seed version: " + payload.getVersion());
        }

        String batchTag = safe(payload.getSource()) == null ? "seed" : safe(payload.getSource());

        int vIns = 0;
        int vSkip = 0;
        int vConflict = 0;
        int vMissing = 0;
        int pIns = 0;
        int pSkip = 0;
        int pConflict = 0;
        int pMissing = 0;
        int deduped = 0;

        List<String> notes = new ArrayList<>();

        List<ResultRow> vendorInsertedRows = new ArrayList<>();
        List<ResultRow> vendorSkippedExistingRows = new ArrayList<>();
        List<ResultRow> vendorConflictedRows = new ArrayList<>();
        List<ResultRow> vendorCanonicalNotFoundRows = new ArrayList<>();

        List<ResultRow> productInsertedRows = new ArrayList<>();
        List<ResultRow> productSkippedExistingRows = new ArrayList<>();
        List<ResultRow> productConflictedRows = new ArrayList<>();
        List<ResultRow> productCanonicalNotFoundRows = new ArrayList<>();

        List<ResultRow> dedupedAliasRows = new ArrayList<>();

        for (AliasSeedPayload.VendorSeed seed : safeList(payload.getVendors())) {
            String canonicalVendorNorm = normalizer.normalizeVendor(seed.getCanonicalVendor());

            if (canonicalVendorNorm == null) {
                vMissing++;
                String message = "Vendor canonical is blank.";
                notes.add(message + " rawCanonical=" + safe(seed.getCanonicalVendor()));
                vendorCanonicalNotFoundRows.add(new ResultRow(
                        "Vendor",
                        safe(seed.getCanonicalVendor()),
                        "-",
                        safe(seed.getCanonicalVendor()),
                        message
                ));
                continue;
            }

            Optional<CpeVendor> canonicalVendorOpt = vendorRepo.findByNameNorm(canonicalVendorNorm);
            if (canonicalVendorOpt.isEmpty()) {
                vMissing++;
                String message = "Canonical vendor not found in cpe_vendors.name_norm.";
                notes.add(message + " canonical=" + canonicalVendorNorm);
                vendorCanonicalNotFoundRows.add(new ResultRow(
                        "Vendor",
                        canonicalVendorNorm,
                        "-",
                        safe(seed.getCanonicalVendor()),
                        message
                ));
                continue;
            }

            Long vendorId = canonicalVendorOpt.get().getId();
            Set<String> seen = new HashSet<>();

            for (AliasSeedPayload.AliasItem item : safeList(seed.getAliases())) {
                String raw = item == null ? null : item.getRaw();
                String aliasNorm = normalizer.normalizeVendor(raw);

                if (aliasNorm == null) {
                    continue;
                }

                if (!seen.add(aliasNorm)) {
                    deduped++;
                    dedupedAliasRows.add(new ResultRow(
                            "Vendor",
                            canonicalVendorNorm,
                            aliasNorm,
                            safe(raw),
                            "Duplicate alias inside this seed JSON."
                    ));
                    continue;
                }

                Optional<CpeVendorAlias> existing =
                        vendorAliasRepo.findFirstByAliasNormAndStatusIgnoreCase(aliasNorm, ACTIVE);

                if (existing.isPresent()) {
                    if (Objects.equals(existing.get().getCpeVendorId(), vendorId)) {
                        vSkip++;
                        vendorSkippedExistingRows.add(new ResultRow(
                                "Vendor",
                                canonicalVendorNorm,
                                aliasNorm,
                                safe(raw),
                                "Already exists for the same canonical vendor. vendorId=" + vendorId
                        ));
                    } else {
                        vConflict++;
                        String detail = "Alias already points to a different vendor. existingVendorId="
                                + existing.get().getCpeVendorId() + ", wantedVendorId=" + vendorId;
                        notes.add("Vendor conflict: canonical=" + canonicalVendorNorm + ", alias=" + aliasNorm);
                        vendorConflictedRows.add(new ResultRow(
                                "Vendor",
                                canonicalVendorNorm,
                                aliasNorm,
                                safe(raw),
                                detail
                        ));
                    }
                    continue;
                }

                int confidence = sanitizeConfidence(item == null ? null : item.getConfidence());
                String evidence = item == null ? null : safe(item.getEvidenceUrl());

                CpeVendorAlias entity = CpeVendorAlias.seeded(
                        vendorId,
                        aliasNorm,
                        batchTag,
                        AliasSource.SEED,
                        AliasReviewState.AUTO,
                        confidence,
                        evidence
                );

                vendorAliasRepo.save(entity);
                vIns++;

                String detail = "Inserted. vendorId=" + vendorId + ", confidence=" + confidence;
                if (evidence != null) {
                    detail += ", evidence=" + evidence;
                }

                vendorInsertedRows.add(new ResultRow(
                        "Vendor",
                        canonicalVendorNorm,
                        aliasNorm,
                        safe(raw),
                        detail
                ));
            }
        }

        for (AliasSeedPayload.ProductSeed seed : safeList(payload.getProducts())) {
            String canonicalVendorNorm = normalizer.normalizeVendor(seed.getCanonicalVendor());
            String canonicalProductNorm = normalizer.normalizeProduct(seed.getCanonicalProduct());

            if (canonicalVendorNorm == null || canonicalProductNorm == null) {
                pMissing++;
                String message = "Canonical vendor/product is blank.";
                notes.add(message + " vendor=" + safe(seed.getCanonicalVendor())
                        + ", product=" + safe(seed.getCanonicalProduct()));
                productCanonicalNotFoundRows.add(new ResultRow(
                        "Product",
                        safe(seed.getCanonicalVendor()) + " / " + safe(seed.getCanonicalProduct()),
                        "-",
                        "-",
                        message
                ));
                continue;
            }

            Optional<CpeVendor> canonicalVendorOpt = vendorRepo.findByNameNorm(canonicalVendorNorm);
            if (canonicalVendorOpt.isEmpty()) {
                pMissing++;
                String message = "Canonical vendor not found for product alias.";
                notes.add(message + " vendor=" + canonicalVendorNorm + ", product=" + canonicalProductNorm);
                productCanonicalNotFoundRows.add(new ResultRow(
                        "Product",
                        canonicalVendorNorm + " / " + canonicalProductNorm,
                        "-",
                        safe(seed.getCanonicalProduct()),
                        message
                ));
                continue;
            }

            Long vendorId = canonicalVendorOpt.get().getId();

            Optional<CpeProduct> canonicalProductOpt =
                    productRepo.findByVendorIdAndNameNorm(vendorId, canonicalProductNorm);

            if (canonicalProductOpt.isEmpty()) {
                pMissing++;
                String message = "Canonical product not found for vendor.";
                notes.add(message + " vendor=" + canonicalVendorNorm + ", product=" + canonicalProductNorm);
                productCanonicalNotFoundRows.add(new ResultRow(
                        "Product",
                        canonicalVendorNorm + " / " + canonicalProductNorm,
                        "-",
                        safe(seed.getCanonicalProduct()),
                        message
                ));
                continue;
            }

            Long productId = canonicalProductOpt.get().getId();
            Set<String> seen = new HashSet<>();

            for (AliasSeedPayload.AliasItem item : safeList(seed.getAliases())) {
                String raw = item == null ? null : item.getRaw();
                String aliasNorm = normalizer.normalizeProduct(raw);

                if (aliasNorm == null) {
                    continue;
                }

                if (!seen.add(aliasNorm)) {
                    deduped++;
                    dedupedAliasRows.add(new ResultRow(
                            "Product",
                            canonicalVendorNorm + " / " + canonicalProductNorm,
                            aliasNorm,
                            safe(raw),
                            "Duplicate alias inside this seed JSON."
                    ));
                    continue;
                }

                Optional<CpeProductAlias> existing =
                        productAliasRepo.findFirstByCpeVendorIdAndAliasNormAndStatusIgnoreCase(vendorId, aliasNorm, ACTIVE);

                if (existing.isPresent()) {
                    if (Objects.equals(existing.get().getCpeProductId(), productId)) {
                        pSkip++;
                        productSkippedExistingRows.add(new ResultRow(
                                "Product",
                                canonicalVendorNorm + " / " + canonicalProductNorm,
                                aliasNorm,
                                safe(raw),
                                "Already exists for the same canonical product. vendorId="
                                        + vendorId + ", productId=" + productId
                        ));
                    } else {
                        pConflict++;
                        String detail = "Alias already points to a different product. existingProductId="
                                + existing.get().getCpeProductId() + ", wantedProductId=" + productId;
                        notes.add("Product conflict: canonical=" + canonicalVendorNorm + "/" + canonicalProductNorm
                                + ", alias=" + aliasNorm);
                        productConflictedRows.add(new ResultRow(
                                "Product",
                                canonicalVendorNorm + " / " + canonicalProductNorm,
                                aliasNorm,
                                safe(raw),
                                detail
                        ));
                    }
                    continue;
                }

                int confidence = sanitizeConfidence(item == null ? null : item.getConfidence());
                String evidence = item == null ? null : safe(item.getEvidenceUrl());

                CpeProductAlias entity = CpeProductAlias.seeded(
                        vendorId,
                        productId,
                        aliasNorm,
                        batchTag,
                        AliasSource.SEED,
                        AliasReviewState.AUTO,
                        confidence,
                        evidence
                );

                productAliasRepo.save(entity);
                pIns++;

                String detail = "Inserted. vendorId=" + vendorId
                        + ", productId=" + productId
                        + ", confidence=" + confidence;
                if (evidence != null) {
                    detail += ", evidence=" + evidence;
                }

                productInsertedRows.add(new ResultRow(
                        "Product",
                        canonicalVendorNorm + " / " + canonicalProductNorm,
                        aliasNorm,
                        safe(raw),
                        detail
                ));
            }
        }

        log.info(
                "Alias seed import done: vIns={} vSkip={} vConflict={} vMissing={} | pIns={} pSkip={} pConflict={} pMissing={} | deduped={}",
                vIns, vSkip, vConflict, vMissing, pIns, pSkip, pConflict, pMissing, deduped
        );

        return new SeedReport(
                vIns,
                vSkip,
                vConflict,
                vMissing,
                pIns,
                pSkip,
                pConflict,
                pMissing,
                deduped,
                notes,
                new ImportDetails(
                        vendorInsertedRows,
                        vendorSkippedExistingRows,
                        vendorConflictedRows,
                        vendorCanonicalNotFoundRows,
                        productInsertedRows,
                        productSkippedExistingRows,
                        productConflictedRows,
                        productCanonicalNotFoundRows,
                        dedupedAliasRows
                )
        );
    }

    private static int sanitizeConfidence(Integer value) {
        int v = value == null ? DEFAULT_CONFIDENCE : value;
        if (v < 0) {
            return 0;
        }
        if (v > 100) {
            return 100;
        }
        return v;
    }

    private static <T> List<T> safeList(List<T> rows) {
        return rows == null ? List.of() : rows;
    }

    private static String safe(String s) {
        if (s == null) {
            return null;
        }
        String v = s.trim();
        return v.isEmpty() ? null : v;
    }
}