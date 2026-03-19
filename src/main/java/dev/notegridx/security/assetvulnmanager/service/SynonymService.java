package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.repository.*;
import org.springframework.stereotype.Service;
import dev.notegridx.security.assetvulnmanager.utility.LruMap;

import java.util.Map;
import java.util.Optional;

@Service
public class SynonymService {

    private static final String ACTIVE = "ACTIVE";

    private final CpeVendorRepository vendorRepository;
    private final CpeProductRepository productRepository;
    private final CpeVendorAliasRepository vendorAliasRepository;
    private final CpeProductAliasRepository productAliasRepository;

    // Small LRU caches to avoid repeated alias and vendor-id lookups
    // during import, matching, and suggestion workflows.
    private final Map<String, String> vendorAliasCache = new LruMap<>(50_000);
    private final Map<String, String> productAliasCache = new LruMap<>(100_000);
    private final Map<String, Long> vendorNormToIdCache = new LruMap<>(50_000);

    public SynonymService(
            CpeVendorRepository vendorRepository,
            CpeProductRepository productRepository,
            CpeVendorAliasRepository vendorAliasRepository,
            CpeProductAliasRepository productAliasRepository
    ) {
        this.vendorRepository = vendorRepository;
        this.productRepository = productRepository;
        this.vendorAliasRepository = vendorAliasRepository;
        this.productAliasRepository = productAliasRepository;
    }

    /**
     * Resolves a normalized vendor name through the vendor alias dictionary.
     * Returns the canonical vendor name when an active alias is found.
     * Otherwise, returns the original normalized input.
     */
    public String canonicalVendorOrSame(String vendorNorm) {
        String v = normalize(vendorNorm);
        if (v == null) return null;

        String cached = vendorAliasCache.get(v);
        if (cached != null) return cached;

        Optional<String> resolved = vendorAliasRepository
                .findFirstByAliasNormAndStatusIgnoreCase(v, ACTIVE)
                .flatMap(a -> vendorRepository.findById(a.getCpeVendorId()))
                .map(cv -> normalize(cv.getNameNorm()));

        String out = resolved.orElse(v);
        vendorAliasCache.put(v, out);
        return out;
    }

    /**
     * Resolves a normalized product name through the product alias dictionary
     * within the scope of a canonical vendor.
     *
     * Product aliases are vendor-scoped because the same product-like token
     * may legitimately map to different canonical products under different vendors.
     *
     * Returns the canonical product name when an active alias is found.
     * Otherwise, returns the original normalized product input.
     */
    public String canonicalProductOrSame(String vendorNorm, String productNorm) {
        String vn = normalize(vendorNorm);
        String pn = normalize(productNorm);
        if (pn == null) return null;
        if (vn == null) return pn;

        String key = vn + "\u0000" + pn;
        String cached = productAliasCache.get(key);
        if (cached != null) return cached;

        Long vendorId = vendorNormToId(vn);
        if (vendorId == null) {
            productAliasCache.put(key, pn);
            return pn;
        }

        Optional<String> resolved = productAliasRepository
                .findFirstByCpeVendorIdAndAliasNormAndStatusIgnoreCase(vendorId, pn, ACTIVE)
                .flatMap(a -> productRepository.findById(a.getCpeProductId()))
                .map(cp -> normalize(cp.getNameNorm()));

        String out = resolved.orElse(pn);
        productAliasCache.put(key, out);
        return out;
    }

    /**
     * Resolves a canonical vendor name to its internal vendor identifier.
     * This lookup is cached because product alias resolution depends on it.
     */
    private Long vendorNormToId(String vendorNorm) {
        Long cached = vendorNormToIdCache.get(vendorNorm);
        if (cached != null) return cached;

        Long id = vendorRepository.findByNameNorm(vendorNorm)
                .map(v -> v.getId())
                .orElse(null);

        if (id != null) vendorNormToIdCache.put(vendorNorm, id);
        return id;
    }

    /**
     * Trims input and converts blank strings to null so lookup behavior stays
     * consistent across import and matching paths.
     */
    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * Clears in-memory lookup caches.
     * Call this after alias master data changes so subsequent resolutions
     * reflect the latest dictionary state.
     */
    public void clearCaches() {
        vendorAliasCache.clear();
        productAliasCache.clear();
        vendorNormToIdCache.clear();
    }
}