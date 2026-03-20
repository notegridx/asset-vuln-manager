package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.repository.*;
import org.springframework.stereotype.Service;
import dev.notegridx.security.assetvulnmanager.utility.LruMap;

import java.util.Map;
import java.util.Optional;

/**
 * Resolves normalized vendor and product names through alias dictionaries.
 *
 * <p>This service sits between raw-name normalization and canonical CPE lookup.
 * Its job is not to guess new values, but to collapse known aliases onto the
 * same canonical vendor/product keys so matching stays deterministic across
 * import, backfill, UI review, and alert generation.
 *
 * <p>Vendor aliases are global. Product aliases are vendor-scoped because the
 * same product-like token may map to different canonical products under
 * different vendors.
 */
@Service
public class SynonymService {

    private static final String ACTIVE = "ACTIVE";

    private final CpeVendorRepository vendorRepository;
    private final CpeProductRepository productRepository;
    private final CpeVendorAliasRepository vendorAliasRepository;
    private final CpeProductAliasRepository productAliasRepository;

    // NOTE: These caches reduce repeated repository lookups on hot paths such as
    // import, canonical linking, and suggestion rendering. They intentionally
    // store resolved canonical values, including "no alias found" fallbacks.
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
     *
     * <p>When an active alias exists, this returns the canonical vendor key used
     * by the CPE dictionary. Otherwise, it returns the original normalized input
     * so downstream lookup can continue without branching on null alias results.
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
     * <p>Product aliases are vendor-scoped by design. Reusing the same alias
     * globally would make short or generic product names drift across vendors.
     *
     * <p>When an active alias exists, this returns the canonical product key.
     * Otherwise, it returns the original normalized product input.
     */
    public String canonicalProductOrSame(String vendorNorm, String productNorm) {
        String vn = normalize(vendorNorm);
        String pn = normalize(productNorm);
        if (pn == null) return null;
        if (vn == null) return pn;

        String key = vn + "\u0000" + pn;
        String cached = productAliasCache.get(key);
        if (cached != null) return cached;

        // Product aliases depend on the canonical vendor ID. If the vendor does
        // not resolve, preserve the product as-is rather than applying a loose
        // cross-vendor alias.
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
     * Resolves a canonical vendor key to its internal vendor ID.
     *
     * <p>This lookup is cached because vendor-scoped product alias resolution
     * depends on it and would otherwise repeat the same repository access for
     * every product under the same vendor.
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
     * Trims input and converts blank strings to null.
     *
     * <p>This keeps alias lookup semantics aligned across services that may pass
     * values with different whitespace quality.
     */
    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * Clears in-memory resolution caches.
     *
     * <p>Call this after alias master data changes so subsequent lookups reflect
     * the latest dictionary state instead of previously cached resolutions.
     */
    public void clearCaches() {
        vendorAliasCache.clear();
        productAliasCache.clear();
        vendorNormToIdCache.clear();
    }
}