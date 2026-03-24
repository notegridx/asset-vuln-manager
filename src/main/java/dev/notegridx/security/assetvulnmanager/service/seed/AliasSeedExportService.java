package dev.notegridx.security.assetvulnmanager.service.seed;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Service
public class AliasSeedExportService {

    private static final String ACTIVE = "ACTIVE";
    private static final int EXPORT_LIMIT = 100_000;

    private final ObjectMapper objectMapper;
    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final CpeVendorRepository vendorRepo;
    private final CpeProductRepository productRepo;

    public AliasSeedExportService(
            ObjectMapper objectMapper,
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            CpeVendorRepository vendorRepo,
            CpeProductRepository productRepo
    ) {
        this.objectMapper = objectMapper;
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.vendorRepo = vendorRepo;
        this.productRepo = productRepo;
    }

    @Transactional(readOnly = true)
    public AliasSeedPayload exportPayload() {
        AliasSeedPayload payload = new AliasSeedPayload();
        payload.setVersion(1);
        payload.setSource("avm-export");

        List<CpeVendorAlias> vendorAliases = loadActiveVendorAliases();
        List<CpeProductAlias> productAliases = loadActiveProductAliases();

        Map<Long, CpeVendor> vendorMap = loadVendorMap(vendorAliases, productAliases);
        Map<Long, CpeProduct> productMap = loadProductMap(productAliases);

        payload.setVendors(buildVendorSeeds(vendorAliases, vendorMap));
        payload.setProducts(buildProductSeeds(productAliases, vendorMap, productMap));

        return payload;
    }

    @Transactional(readOnly = true)
    public String exportJson() {
        try {
            return objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(exportPayload());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to export alias seed JSON", e);
        }
    }

    private List<CpeVendorAlias> loadActiveVendorAliases() {
        List<CpeVendorAlias> rows = vendorAliasRepo.search(
                null,
                ACTIVE,
                PageRequest.of(0, EXPORT_LIMIT)
        );

        rows.sort(Comparator
                .comparing(CpeVendorAlias::getCpeVendorId, Comparator.nullsLast(Long::compareTo))
                .thenComparing(CpeVendorAlias::getAliasNorm, Comparator.nullsLast(String::compareToIgnoreCase))
                .thenComparing(CpeVendorAlias::getId, Comparator.nullsLast(Long::compareTo)));

        return rows;
    }

    private List<CpeProductAlias> loadActiveProductAliases() {
        List<CpeProductAlias> rows = productAliasRepo.search(
                null,
                null,
                ACTIVE,
                PageRequest.of(0, EXPORT_LIMIT)
        );

        rows.sort(Comparator
                .comparing(CpeProductAlias::getCpeVendorId, Comparator.nullsLast(Long::compareTo))
                .thenComparing(CpeProductAlias::getCpeProductId, Comparator.nullsLast(Long::compareTo))
                .thenComparing(CpeProductAlias::getAliasNorm, Comparator.nullsLast(String::compareToIgnoreCase))
                .thenComparing(CpeProductAlias::getId, Comparator.nullsLast(Long::compareTo)));

        return rows;
    }

    private Map<Long, CpeVendor> loadVendorMap(
            List<CpeVendorAlias> vendorAliases,
            List<CpeProductAlias> productAliases
    ) {
        Set<Long> ids = new HashSet<>();

        for (CpeVendorAlias row : vendorAliases) {
            if (row.getCpeVendorId() != null) {
                ids.add(row.getCpeVendorId());
            }
        }
        for (CpeProductAlias row : productAliases) {
            if (row.getCpeVendorId() != null) {
                ids.add(row.getCpeVendorId());
            }
        }

        Map<Long, CpeVendor> map = new LinkedHashMap<>();
        for (CpeVendor vendor : vendorRepo.findAllById(ids)) {
            map.put(vendor.getId(), vendor);
        }
        return map;
    }

    private Map<Long, CpeProduct> loadProductMap(List<CpeProductAlias> productAliases) {
        Set<Long> ids = new HashSet<>();
        for (CpeProductAlias row : productAliases) {
            if (row.getCpeProductId() != null) {
                ids.add(row.getCpeProductId());
            }
        }

        Map<Long, CpeProduct> map = new LinkedHashMap<>();
        for (CpeProduct product : productRepo.findAllById(ids)) {
            map.put(product.getId(), product);
        }
        return map;
    }

    private List<AliasSeedPayload.VendorSeed> buildVendorSeeds(
            List<CpeVendorAlias> rows,
            Map<Long, CpeVendor> vendorMap
    ) {
        Map<String, AliasSeedPayload.VendorSeed> grouped = new LinkedHashMap<>();
        Map<String, Set<String>> seen = new LinkedHashMap<>();

        for (CpeVendorAlias row : rows) {
            if (row == null || isBlank(row.getAliasNorm()) || row.getCpeVendorId() == null) {
                continue;
            }

            CpeVendor vendor = vendorMap.get(row.getCpeVendorId());
            if (vendor == null || isBlank(vendor.getNameNorm())) {
                continue;
            }

            String canonicalVendor = vendor.getNameNorm();

            AliasSeedPayload.VendorSeed seed = grouped.computeIfAbsent(canonicalVendor, key -> {
                AliasSeedPayload.VendorSeed s = new AliasSeedPayload.VendorSeed();
                s.setCanonicalVendor(key);
                return s;
            });

            Set<String> seenAliases = seen.computeIfAbsent(canonicalVendor, key -> new HashSet<>());
            String aliasNorm = row.getAliasNorm().trim();

            if (!seenAliases.add(aliasNorm)) {
                continue;
            }

            AliasSeedPayload.AliasItem item = new AliasSeedPayload.AliasItem();
            item.setRaw(aliasNorm);
            item.setConfidence(row.getConfidence());
            item.setEvidenceUrl(blankToNull(row.getEvidenceUrl()));
            seed.getAliases().add(item);
        }

        return new ArrayList<>(grouped.values());
    }

    private List<AliasSeedPayload.ProductSeed> buildProductSeeds(
            List<CpeProductAlias> rows,
            Map<Long, CpeVendor> vendorMap,
            Map<Long, CpeProduct> productMap
    ) {
        Map<String, AliasSeedPayload.ProductSeed> grouped = new LinkedHashMap<>();
        Map<String, Set<String>> seen = new LinkedHashMap<>();

        for (CpeProductAlias row : rows) {
            if (row == null
                    || isBlank(row.getAliasNorm())
                    || row.getCpeVendorId() == null
                    || row.getCpeProductId() == null) {
                continue;
            }

            CpeVendor vendor = vendorMap.get(row.getCpeVendorId());
            CpeProduct product = productMap.get(row.getCpeProductId());

            if (vendor == null || product == null) {
                continue;
            }
            if (isBlank(vendor.getNameNorm()) || isBlank(product.getNameNorm())) {
                continue;
            }

            String canonicalVendor = vendor.getNameNorm();
            String canonicalProduct = product.getNameNorm();

            if (product.getVendor() == null
                    || !Objects.equals(product.getVendor().getId(), vendor.getId())) {
                continue;
            }

            String groupKey = canonicalVendor + "||" + canonicalProduct;

            AliasSeedPayload.ProductSeed seed = grouped.computeIfAbsent(groupKey, key -> {
                AliasSeedPayload.ProductSeed s = new AliasSeedPayload.ProductSeed();
                s.setCanonicalVendor(canonicalVendor);
                s.setCanonicalProduct(canonicalProduct);
                return s;
            });

            Set<String> seenAliases = seen.computeIfAbsent(groupKey, key -> new HashSet<>());
            String aliasNorm = row.getAliasNorm().trim();

            if (!seenAliases.add(aliasNorm)) {
                continue;
            }

            AliasSeedPayload.AliasItem item = new AliasSeedPayload.AliasItem();
            item.setRaw(aliasNorm);
            item.setConfidence(row.getConfidence());
            item.setEvidenceUrl(blankToNull(row.getEvidenceUrl()));
            seed.getAliases().add(item);
        }

        return new ArrayList<>(grouped.values());
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        return v.isEmpty() ? null : v;
    }
}