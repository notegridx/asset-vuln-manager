package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import java.util.HashMap;
import java.util.Map;

@Service
public class AdminInventoryReadService {

    private final ImportRunRepository importRunRepository;
    private final UnresolvedMappingRepository unresolvedMappingRepository;
    private final SoftwareInstallRepository softwareInstallRepository;
    private final CanonicalCpeLinkingService canonicalCpeLinkingService;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    public AdminInventoryReadService(
            ImportRunRepository importRunRepository,
            UnresolvedMappingRepository unresolvedMappingRepository,
            SoftwareInstallRepository softwareInstallRepository,
            CanonicalCpeLinkingService canonicalCpeLinkingService,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository
    ) {
        this.importRunRepository = importRunRepository;
        this.unresolvedMappingRepository = unresolvedMappingRepository;
        this.softwareInstallRepository = softwareInstallRepository;
        this.canonicalCpeLinkingService = canonicalCpeLinkingService;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
    }

    @Transactional(readOnly = true)
    public List<ImportRun> findImportRuns() {
        List<ImportRun> runs = new ArrayList<>(importRunRepository.findAll());
        runs.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });
        return runs;
    }

    @Transactional(readOnly = true)
    public UnresolvedListView findUnresolvedMappings(
            String status,
            Long runId,
            String q,
            Boolean activeOnly,
            String activeOnlyPresent,
            Long id
    ) {
        String effectiveQ = normalize(q);
        String effectiveStatus = normalizeStatus(status);

        if (id != null) {
            List<UnresolvedReviewRow> list = unresolvedMappingRepository.findById(id)
                    .map(this::toReviewRow)
                    .map(List::of)
                    .orElseGet(List::of);

            if (effectiveQ != null) {
                String needle = effectiveQ.toLowerCase(Locale.ROOT);
                list = list.stream()
                        .filter(r -> containsIgnoreCase(r.getVendorRaw(), needle)
                                || containsIgnoreCase(r.getProductRaw(), needle))
                        .toList();
            }

            return new UnresolvedListView(
                    list,
                    effectiveStatus,
                    runId,
                    effectiveQ,
                    false,
                    null,
                    id
            );
        }

        List<UnresolvedMapping> mappings = new ArrayList<>(unresolvedMappingRepository.findAll());

        Map<String, UnresolvedMapping> mappingByNormalizedPair = new HashMap<>();
        Map<String, UnresolvedMapping> mappingByRawPair = new HashMap<>();

        for (UnresolvedMapping mapping : mappings) {
            String normalizedPairKey = pairKey(
                    mapping.getNormalizedVendor(),
                    mapping.getNormalizedProduct()
            );
            if (normalizedPairKey != null) {
                putIfNewer(mappingByNormalizedPair, normalizedPairKey, mapping);
            }

            String rawPairKey = pairKey(
                    mapping.getVendorRaw(),
                    mapping.getProductRaw()
            );
            if (rawPairKey != null) {
                putIfNewer(mappingByRawPair, rawPairKey, mapping);
            }
        }

        List<UnresolvedReviewRow> list = softwareInstallRepository.findAll().stream()
                .map(install -> toReviewRow(
                        install,
                        findBestMappingForInstall(install, mappingByNormalizedPair, mappingByRawPair)
                ))
                .toList();

        if (!"all".equals(effectiveStatus)) {
            list = list.stream()
                    .filter(r -> matchesStatus(r, effectiveStatus))
                    .toList();
        }

        if (effectiveQ != null) {
            String needle = effectiveQ.toLowerCase(Locale.ROOT);
            list = list.stream()
                    .filter(r -> containsIgnoreCase(r.getVendorRaw(), needle)
                            || containsIgnoreCase(r.getProductRaw(), needle))
                    .toList();
        }

        list = list.stream()
                .sorted((a, b) -> Long.compare(sortId(b), sortId(a)))
                .toList();

        return new UnresolvedListView(
                list,
                effectiveStatus,
                runId,
                effectiveQ,
                false,
                null,
                null
        );
    }

    private UnresolvedReviewRow toReviewRow(UnresolvedMapping mapping) {
        List<SoftwareInstall> related = loadRelatedSoftware(mapping);
        CanonicalStatusView status = summarizeStatus(mapping, related);
        LinkedCanonicalView linked = summarizeLinkedCanonical(mapping, related);

        return new UnresolvedReviewRow(
                mapping.getId(),
                null,
                mapping,
                mapping.getVendorRaw(),
                mapping.getProductRaw(),
                mapping.getVersionRaw(),
                mapping.getNormalizedVendor(),
                mapping.getNormalizedProduct(),
                safeCandidateVendorIds(mapping),
                safeCandidateProductIds(mapping),
                status,
                linked.vendorId(),
                linked.productId(),
                linked.vendorName(),
                linked.productName()
        );
    }

    private UnresolvedReviewRow toReviewRow(SoftwareInstall install, UnresolvedMapping mapping) {
        List<SoftwareInstall> related = List.of(install);
        CanonicalStatusView status = summarizeStatus(mapping, related);
        LinkedCanonicalView linked = summarizeLinkedCanonical(mapping, related);

        return new UnresolvedReviewRow(
                mapping != null ? mapping.getId() : null,
                install.getId(),
                mapping,
                firstNonBlank(install.getVendorRaw(), mapping != null ? mapping.getVendorRaw() : null),
                firstNonBlank(install.getProductRaw(), mapping != null ? mapping.getProductRaw() : null),
                firstNonBlank(install.getVersionRaw(), mapping != null ? mapping.getVersionRaw() : null),
                firstNonBlank(install.getNormalizedVendor(), mapping != null ? mapping.getNormalizedVendor() : null),
                firstNonBlank(install.getNormalizedProduct(), mapping != null ? mapping.getNormalizedProduct() : null),
                mapping != null ? safeCandidateVendorIds(mapping) : null,
                mapping != null ? safeCandidateProductIds(mapping) : null,
                status,
                linked.vendorId(),
                linked.productId(),
                linked.vendorName(),
                linked.productName()
        );
    }

    private List<SoftwareInstall> loadRelatedSoftware(UnresolvedMapping mapping) {
        String normalizedVendor = normalize(mapping.getNormalizedVendor());
        String normalizedProduct = normalize(mapping.getNormalizedProduct());
        String rawVendor = normalize(mapping.getVendorRaw());
        String rawProduct = normalize(mapping.getProductRaw());

        List<SoftwareInstall> all = softwareInstallRepository.findAll();

        if (normalizedVendor == null && normalizedProduct == null && rawVendor == null && rawProduct == null) {
            return List.of();
        }

        List<SoftwareInstall> exactNormalized = all.stream()
                .filter(s -> Objects.equals(normalize(s.getNormalizedVendor()), normalizedVendor))
                .filter(s -> Objects.equals(normalize(s.getNormalizedProduct()), normalizedProduct))
                .toList();

        if (!exactNormalized.isEmpty()) {
            return exactNormalized;
        }

        List<SoftwareInstall> exactRaw = all.stream()
                .filter(s -> Objects.equals(normalize(s.getVendorRaw()), rawVendor))
                .filter(s -> Objects.equals(normalize(s.getProductRaw()), rawProduct))
                .toList();

        if (!exactRaw.isEmpty()) {
            return exactRaw;
        }

        if (normalizedVendor != null) {
            List<SoftwareInstall> vendorOnlyNormalized = all.stream()
                    .filter(s -> Objects.equals(normalize(s.getNormalizedVendor()), normalizedVendor))
                    .toList();
            if (!vendorOnlyNormalized.isEmpty()) {
                return vendorOnlyNormalized;
            }
        }

        if (rawVendor != null) {
            List<SoftwareInstall> vendorOnlyRaw = all.stream()
                    .filter(s -> Objects.equals(normalize(s.getVendorRaw()), rawVendor))
                    .toList();
            if (!vendorOnlyRaw.isEmpty()) {
                return vendorOnlyRaw;
            }
        }

        if (normalizedProduct != null) {
            List<SoftwareInstall> productOnlyNormalized = all.stream()
                    .filter(s -> Objects.equals(normalize(s.getNormalizedProduct()), normalizedProduct))
                    .toList();
            if (!productOnlyNormalized.isEmpty()) {
                return productOnlyNormalized;
            }
        }

        if (rawProduct != null) {
            return all.stream()
                    .filter(s -> Objects.equals(normalize(s.getProductRaw()), rawProduct))
                    .toList();
        }

        return List.of();
    }

    private CanonicalStatusView summarizeStatus(UnresolvedMapping mapping, List<SoftwareInstall> installs) {
        if (installs != null && !installs.isEmpty()) {
            boolean hasLinkedValid = false;
            boolean hasVendorOnlyLinked = false;
            boolean hasNeedsNormalization = false;
            boolean hasResolvable = false;
            boolean hasVendorResolvableOnly = false;
            boolean hasUnresolvable = false;
            boolean hasNotLinked = false;

            for (SoftwareInstall s : installs) {
                CanonicalCpeLinkingService.Analysis analysis = canonicalCpeLinkingService.analyze(s);
                if (analysis == null) {
                    continue;
                }

                if (analysis.fullyLinkedSql()) {
                    hasLinkedValid = true;
                }
                if (analysis.vendorOnlyLinkedSql()) {
                    hasVendorOnlyLinked = true;
                }
                if (analysis.needsNormalization()) {
                    hasNeedsNormalization = true;
                }
                if (analysis.dictFullyResolvable()) {
                    hasResolvable = true;
                }
                if (analysis.dictVendorResolvableOnly()) {
                    hasVendorResolvableOnly = true;
                }
                if (analysis.dictUnresolvable()) {
                    hasUnresolvable = true;
                }
                if (analysis.notLinkedSql()) {
                    hasNotLinked = true;
                }
            }

            if (hasLinkedValid) {
                return CanonicalStatusView.LINKED_VALID;
            }
            if (hasVendorOnlyLinked) {
                return CanonicalStatusView.VENDOR_ONLY_LINKED;
            }
            if (hasNeedsNormalization) {
                return CanonicalStatusView.NEEDS_NORMALIZATION;
            }
            if (hasResolvable) {
                return CanonicalStatusView.RESOLVABLE;
            }
            if (hasVendorResolvableOnly) {
                return CanonicalStatusView.VENDOR_RESOLVABLE_ONLY;
            }
            if (hasUnresolvable) {
                return CanonicalStatusView.UNRESOLVABLE;
            }
            if (hasNotLinked) {
                return CanonicalStatusView.NOT_LINKED;
            }
        }

        if (mapping != null) {
            Long linkedVendorId = mapping.getLinkedCpeVendorId();
            Long linkedProductId = mapping.getLinkedCpeProductId();

            if (linkedVendorId != null && linkedProductId != null) {
                return CanonicalStatusView.LINKED_VALID;
            }
            if (linkedVendorId != null) {
                return CanonicalStatusView.VENDOR_ONLY_LINKED;
            }
        }

        return CanonicalStatusView.UNRESOLVABLE;
    }

    private LinkedCanonicalView summarizeLinkedCanonical(UnresolvedMapping mapping, List<SoftwareInstall> installs) {
        if (installs != null && !installs.isEmpty()) {
            SoftwareInstall representative = installs.stream()
                    .filter(s -> s.getCpeVendorId() != null && s.getCpeProductId() != null)
                    .findFirst()
                    .orElseGet(() -> installs.stream()
                            .filter(s -> s.getCpeVendorId() != null)
                            .findFirst()
                            .orElse(null));

            if (representative != null) {
                Long vendorId = representative.getCpeVendorId();
                Long productId = representative.getCpeProductId();

                String vendorName = null;
                String productName = null;

                if (vendorId != null) {
                    vendorName = cpeVendorRepository.findById(vendorId)
                            .map(v -> firstNonBlank(v.getDisplayName(), v.getNameNorm()))
                            .orElse(null);
                }

                if (productId != null) {
                    productName = cpeProductRepository.findById(productId)
                            .map(p -> firstNonBlank(p.getDisplayName(), p.getNameNorm()))
                            .orElse(null);
                }

                return new LinkedCanonicalView(
                        vendorId,
                        productId,
                        vendorName,
                        productName
                );
            }
        }

        if (mapping != null) {
            Long mappedVendorId = mapping.getLinkedCpeVendorId();
            Long mappedProductId = mapping.getLinkedCpeProductId();

            if (mappedVendorId != null || mappedProductId != null) {
                String vendorName = null;
                String productName = null;

                if (mappedVendorId != null) {
                    vendorName = cpeVendorRepository.findById(mappedVendorId)
                            .map(v -> firstNonBlank(v.getDisplayName(), v.getNameNorm()))
                            .orElse(null);
                }

                if (mappedProductId != null) {
                    productName = cpeProductRepository.findById(mappedProductId)
                            .map(p -> firstNonBlank(p.getDisplayName(), p.getNameNorm()))
                            .orElse(null);
                }

                return new LinkedCanonicalView(
                        mappedVendorId,
                        mappedProductId,
                        vendorName,
                        productName
                );
            }
        }

        return LinkedCanonicalView.empty();
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        if (b != null && !b.isBlank()) {
            return b;
        }
        return null;
    }

    private static boolean matchesStatus(UnresolvedReviewRow row, String effectiveStatus) {
        return switch (effectiveStatus) {
            case "all" -> true;
            case "fullyLinked" -> row.statusView == CanonicalStatusView.LINKED_VALID
                    || row.statusView == CanonicalStatusView.LINKED_STALE;
            case "vendorOnlyLinked" -> row.statusView == CanonicalStatusView.VENDOR_ONLY_LINKED;
            case "notLinked" -> row.statusView == CanonicalStatusView.NOT_LINKED
                    || row.statusView == CanonicalStatusView.RESOLVABLE
                    || row.statusView == CanonicalStatusView.VENDOR_RESOLVABLE_ONLY
                    || row.statusView == CanonicalStatusView.UNRESOLVABLE
                    || row.statusView == CanonicalStatusView.NEEDS_NORMALIZATION;
            case "linkedValid" -> row.statusView == CanonicalStatusView.LINKED_VALID;
            case "linkedStale" -> row.statusView == CanonicalStatusView.LINKED_STALE;
            case "fullyResolvable" -> row.statusView == CanonicalStatusView.RESOLVABLE;
            case "vendorResolvableOnly" -> row.statusView == CanonicalStatusView.VENDOR_RESOLVABLE_ONLY;
            case "unresolvable" -> row.statusView == CanonicalStatusView.UNRESOLVABLE;
            case "needsNormalization" -> row.statusView == CanonicalStatusView.NEEDS_NORMALIZATION;
            default -> true;
        };
    }

    private static String normalizeStatus(String status) {
        if (status == null || status.isBlank()) {
            return "all";
        }

        String normalized = status.trim();

        return switch (normalized) {
            case "ALL", "all" -> "all";

            case "NEW", "new" -> "all";

            case "LINKED", "linked",
                 "FULLY_LINKED", "fully_linked",
                 "FULLYLINKED", "fullylinked",
                 "fullyLinked" -> "fullyLinked";

            case "VENDOR_LINKED", "vendor_linked",
                 "VENDOR_ONLY_LINKED", "vendor_only_linked",
                 "VENDORONLYLINKED", "vendoronlylinked",
                 "VENDORONLYLINKEDSQL", "vendoronlylinkedsql",
                 "vendorOnlyLinked" -> "vendorOnlyLinked";

            case "NOT_LINKED", "not_linked",
                 "NOTLINKED", "notlinked",
                 "notLinked" -> "notLinked";

            case "LINKED_VALID", "linked_valid",
                 "LINKEDVALID", "linkedvalid",
                 "linkedValid" -> "linkedValid";

            case "LINKED_STALE", "linked_stale",
                 "LINKEDSTALE", "linkedstale",
                 "linkedStale" -> "linkedStale";

            case "RESOLVABLE", "resolvable",
                 "FULLY_RESOLVABLE", "fully_resolvable",
                 "FULLYRESOLVABLE", "fullyresolvable",
                 "fullyResolvable" -> "fullyResolvable";

            case "VENDOR_RESOLVABLE_ONLY", "vendor_resolvable_only",
                 "VENDORRESOLVABLEONLY", "vendorresolvableonly",
                 "vendorResolvableOnly" -> "vendorResolvableOnly";

            case "UNRESOLVABLE", "unresolvable" -> "unresolvable";

            case "NEEDS_NORMALIZATION", "needs_normalization",
                 "NEEDSNORMALIZATION", "needsnormalization",
                 "needsNormalization" -> "needsNormalization";

            case "RESOLVED", "resolved" -> "fullyLinked";

            default -> normalized;
        };
    }

    private static boolean containsIgnoreCase(String value, String needleLower) {
        if (value == null || needleLower == null) {
            return false;
        }
        return value.toLowerCase(Locale.ROOT).contains(needleLower);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String pairKey(String a, String b) {
        String left = normalize(a);
        String right = normalize(b);

        if (left == null && right == null) {
            return null;
        }

        return (left == null ? "" : left) + "\u0000" + (right == null ? "" : right);
    }

    private static void putIfNewer(Map<String, UnresolvedMapping> map, String key, UnresolvedMapping mapping) {
        UnresolvedMapping existing = map.get(key);

        if (existing == null) {
            map.put(key, mapping);
            return;
        }

        Long existingId = existing.getId();
        Long newId = mapping.getId();

        if (existingId == null || (newId != null && newId > existingId)) {
            map.put(key, mapping);
        }
    }

    private UnresolvedMapping findBestMappingForInstall(
            SoftwareInstall install,
            Map<String, UnresolvedMapping> mappingByNormalizedPair,
            Map<String, UnresolvedMapping> mappingByRawPair
    ) {
        String normalizedPairKey = pairKey(
                install.getNormalizedVendor(),
                install.getNormalizedProduct()
        );
        if (normalizedPairKey != null) {
            UnresolvedMapping hit = mappingByNormalizedPair.get(normalizedPairKey);
            if (hit != null) {
                return hit;
            }
        }

        String rawPairKey = pairKey(
                install.getVendorRaw(),
                install.getProductRaw()
        );
        if (rawPairKey != null) {
            return mappingByRawPair.get(rawPairKey);
        }

        return null;
    }

    private static long sortId(UnresolvedReviewRow row) {
        if (row.getSoftwareInstallId() != null) {
            return row.getSoftwareInstallId();
        }
        if (row.getId() != null) {
            return row.getId();
        }
        return Long.MIN_VALUE;
    }

    private static String safeCandidateVendorIds(UnresolvedMapping mapping) {
        try {
            return mapping.getCandidateVendorIds();
        } catch (Exception e) {
            return null;
        }
    }

    private static String safeCandidateProductIds(UnresolvedMapping mapping) {
        try {
            return mapping.getCandidateProductIds();
        } catch (Exception e) {
            return null;
        }
    }

    public enum CanonicalStatusView {
        LINKED_VALID("linkedValid", "LINKED"),
        LINKED_STALE("linkedStale", "LINKED STALE"),
        VENDOR_ONLY_LINKED("vendorOnlyLinked", "VENDOR ONLY LINKED"),
        NOT_LINKED("notLinked", "NOT LINKED"),
        RESOLVABLE("fullyResolvable", "RESOLVABLE"),
        VENDOR_RESOLVABLE_ONLY("vendorResolvableOnly", "VENDOR RESOLVABLE ONLY"),
        UNRESOLVABLE("unresolvable", "UNRESOLVABLE"),
        NEEDS_NORMALIZATION("needsNormalization", "NEEDS NORMALIZATION");

        private final String key;
        private final String label;

        CanonicalStatusView(String key, String label) {
            this.key = key;
            this.label = label;
        }

        public String label() {
            return label;
        }

        public String key() {
            return key;
        }
    }

    public record UnresolvedReviewRow(
            Long id,
            Long softwareInstallId,
            UnresolvedMapping mapping,
            String vendorRaw,
            String productRaw,
            String versionRaw,
            String normalizedVendor,
            String normalizedProduct,
            String candidateVendorIds,
            String candidateProductIds,
            CanonicalStatusView statusView,
            Long linkedCpeVendorId,
            Long linkedCpeProductId,
            String linkedVendorName,
            String linkedProductName
    ) {
        public Long getId() {
            return id;
        }

        public Long getSoftwareInstallId() {
            return softwareInstallId;
        }

        public String getVendorRaw() {
            return vendorRaw;
        }

        public String getProductRaw() {
            return productRaw;
        }

        public String getVersionRaw() {
            return versionRaw;
        }

        public String getNormalizedVendor() {
            return normalizedVendor;
        }

        public String getNormalizedProduct() {
            return normalizedProduct;
        }

        public String getCandidateVendorIds() {
            return candidateVendorIds;
        }

        public String getCandidateProductIds() {
            return candidateProductIds;
        }

        public Long getLinkedCpeVendorId() {
            return linkedCpeVendorId;
        }

        public Long getLinkedCpeProductId() {
            return linkedCpeProductId;
        }

        public String getLinkedVendorName() {
            return linkedVendorName;
        }

        public String getLinkedProductName() {
            return linkedProductName;
        }

        public String getStatus() {
            return statusView.key();
        }

        public String getStatusLabel() {
            return statusView.label();
        }

        public UnresolvedMapping raw() {
            return mapping;
        }
    }

    private record LinkedCanonicalView(
            Long vendorId,
            Long productId,
            String vendorName,
            String productName
    ) {
        private static LinkedCanonicalView empty() {
            return new LinkedCanonicalView(null, null, null, null);
        }
    }

    public record UnresolvedListView(
            List<UnresolvedReviewRow> mappings,
            String status,
            Long runId,
            String q,
            boolean activeOnly,
            String activeOnlyPresent,
            Long id
    ) {
    }
}