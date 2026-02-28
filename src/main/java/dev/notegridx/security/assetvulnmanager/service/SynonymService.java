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

    // small LRU caches (same style as other services)
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
     * vendorNorm（正規化済み）を、alias辞書で canonical vendorNorm に寄せる。
     * 見つからなければ入力をそのまま返す。
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
     * productNorm（正規化済み）を、vendorスコープ付き alias辞書で canonical productNorm に寄せる。
     * 見つからなければ入力をそのまま返す。
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

    private Long vendorNormToId(String vendorNorm) {
        Long cached = vendorNormToIdCache.get(vendorNorm);
        if (cached != null) return cached;

        Long id = vendorRepository.findByNameNorm(vendorNorm)
                .map(v -> v.getId())
                .orElse(null);

        if (id != null) vendorNormToIdCache.put(vendorNorm, id);
        return id;
    }

    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    public void clearCaches() {
        vendorAliasCache.clear();
        productAliasCache.clear();
        vendorNormToIdCache.clear();
    }
}