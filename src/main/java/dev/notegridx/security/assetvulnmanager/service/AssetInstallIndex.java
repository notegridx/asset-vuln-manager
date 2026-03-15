package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class AssetInstallIndex {

    private static final String SEP = "\u0001";

    private final List<SoftwareInstall> all;
    private final Map<String, List<SoftwareInstall>> byCanonicalPair;
    private final Map<String, List<SoftwareInstall>> byNormPair;
    private final Map<String, List<SoftwareInstall>> byCpeName;

    private AssetInstallIndex(
            List<SoftwareInstall> all,
            Map<String, List<SoftwareInstall>> byCanonicalPair,
            Map<String, List<SoftwareInstall>> byNormPair,
            Map<String, List<SoftwareInstall>> byCpeName
    ) {
        this.all = all;
        this.byCanonicalPair = byCanonicalPair;
        this.byNormPair = byNormPair;
        this.byCpeName = byCpeName;
    }

    static AssetInstallIndex empty() {
        return new AssetInstallIndex(
                List.of(),
                Map.of(),
                Map.of(),
                Map.of()
        );
    }

    static AssetInstallIndex from(List<SoftwareInstall> installs) {
        if (installs == null || installs.isEmpty()) {
            return empty();
        }

        List<SoftwareInstall> all = new ArrayList<>(installs.size());
        Map<String, List<SoftwareInstall>> byCanonicalPair = new LinkedHashMap<>();
        Map<String, List<SoftwareInstall>> byNormPair = new LinkedHashMap<>();
        Map<String, List<SoftwareInstall>> byCpeName = new LinkedHashMap<>();

        for (SoftwareInstall si : installs) {
            if (si == null) {
                continue;
            }

            all.add(si);

            if (si.getCpeVendorId() != null && si.getCpeProductId() != null) {
                String key = canonicalKey(si.getCpeVendorId(), si.getCpeProductId());
                byCanonicalPair.computeIfAbsent(key, k -> new ArrayList<>()).add(si);
            }

            String vendorNorm = normalize(si.getNormalizedVendor());
            String productNorm = normalize(si.getNormalizedProduct());
            if (vendorNorm != null && productNorm != null) {
                String key = normKey(vendorNorm, productNorm);
                byNormPair.computeIfAbsent(key, k -> new ArrayList<>()).add(si);
            }

            String cpeName = normalize(si.getCpeName());
            if (cpeName != null) {
                byCpeName.computeIfAbsent(cpeName, k -> new ArrayList<>()).add(si);
            }
        }

        return new AssetInstallIndex(
                Collections.unmodifiableList(all),
                freeze(byCanonicalPair),
                freeze(byNormPair),
                freeze(byCpeName)
        );
    }

    List<SoftwareInstall> all() {
        return all;
    }

    boolean isEmpty() {
        return all.isEmpty();
    }

    List<SoftwareInstall> findCandidates(CriteriaTreeLoader.CriteriaCpePredicate predicate) {
        if (predicate == null) {
            return List.of();
        }

        Set<SoftwareInstall> out = new LinkedHashSet<>();

        if (predicate.cpeVendorId() != null && predicate.cpeProductId() != null) {
            out.addAll(byCanonicalPair.getOrDefault(
                    canonicalKey(predicate.cpeVendorId(), predicate.cpeProductId()),
                    List.of()
            ));
        }

        String vendorNorm = normalize(predicate.vendorNorm());
        String productNorm = normalize(predicate.productNorm());
        if (vendorNorm != null && productNorm != null) {
            out.addAll(byNormPair.getOrDefault(
                    normKey(vendorNorm, productNorm),
                    List.of()
            ));
        }

        String cpeName = normalize(predicate.cpeName());
        if (cpeName != null) {
            out.addAll(byCpeName.getOrDefault(cpeName, List.of()));
        }

        if (out.isEmpty()) {
            return List.of();
        }

        return List.copyOf(out);
    }

    private static Map<String, List<SoftwareInstall>> freeze(Map<String, List<SoftwareInstall>> src) {
        Map<String, List<SoftwareInstall>> out = new LinkedHashMap<>();
        for (Map.Entry<String, List<SoftwareInstall>> e : src.entrySet()) {
            out.put(e.getKey(), List.copyOf(e.getValue()));
        }
        return Collections.unmodifiableMap(out);
    }

    private static String canonicalKey(Long vendorId, Long productId) {
        return vendorId + SEP + productId;
    }

    private static String normKey(String vendorNorm, String productNorm) {
        return vendorNorm + SEP + productNorm;
    }

    private static String normalize(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }
}