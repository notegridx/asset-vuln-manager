package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class CanonicalBackfillService {

    private static final Logger log = LoggerFactory.getLogger(CanonicalBackfillService.class);

    private static final int TX_CHUNK = 5_000;
    private static final int LOG_EVERY = 10_000;
    private static final int FLUSH_EVERY = 2_000;

    private static final int CAND_LIMIT = 20;

    private final SoftwareInstallRepository softwareRepo;
    private final CanonicalCpeLinkingService linker;

    private final UnresolvedMappingRepository unresolvedMappingRepository;
    private final VendorProductNormalizer normalizer;

    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    private final EntityManager em;
    private final TransactionTemplate chunkTx;

    public CanonicalBackfillService(
            SoftwareInstallRepository softwareRepo,
            CanonicalCpeLinkingService linker,
            UnresolvedMappingRepository unresolvedMappingRepository,
            VendorProductNormalizer normalizer,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            EntityManager em,
            PlatformTransactionManager txManager
    ) {
        this.softwareRepo = softwareRepo;
        this.linker = linker;
        this.unresolvedMappingRepository = unresolvedMappingRepository;
        this.normalizer = normalizer;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.em = em;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.chunkTx = tt;
    }

    public BackfillResult backfill(int maxRows, boolean forceRebuild) {
        int safeMax = Math.max(1, Math.min(maxRows, 5_000_000));

        int scanned = 0;
        int linked = 0;
        int missed = 0;

        List<SoftwareInstall> all = forceRebuild
                ? softwareRepo.findAll()
                : softwareRepo.findNeedsCanonicalLink();

        // 同一 backfill 実行中の unresolved upsert を dedupe
        Set<String> unresolvedSeen = new HashSet<>();

        for (int offset = 0; offset < all.size() && scanned < safeMax; offset += TX_CHUNK) {
            int to = Math.min(all.size(), offset + TX_CHUNK);
            List<SoftwareInstall> chunk = all.subList(offset, to);

            int remaining = safeMax - scanned;

            int[] result = chunkTx.execute(status -> {
                int processedInChunk = 0;
                int _linked = 0;
                int _missed = 0;

                for (SoftwareInstall s : chunk) {
                    if (processedInChunk >= remaining) break;

                    boolean fullyLinked = (s.getCpeVendorId() != null && s.getCpeProductId() != null);
                    if (fullyLinked && !forceRebuild) {
                        processedInChunk++;
                        continue;
                    }

                    var res = linker.resolve(s);

                    String vendorIn = coalesceNullable(s.getVendorRaw(), s.getVendor());
                    String productIn = coalesceNullable(s.getProductRaw(), s.getProduct());
                    String versionIn = coalesceNullable(s.getVersionRaw(), s.getVersion());
                    String sourceIn = safeString(s.getSource());

                    if (res.hit() && !s.isCanonicalLinkDisabled()) {
                        s.linkCanonical(res.vendorId(), res.productId());
                        _linked++;
                    } else if (res.vendorId() != null) {
                        // vendor-only を先に埋める
                        s.linkCanonical(res.vendorId(), null);
                        _linked++;

                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                        _missed++;
                    } else {
                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                        _missed++;
                    }

                    processedInChunk++;

                    if (processedInChunk % FLUSH_EVERY == 0) {
                        em.flush();
                        em.clear();
                    }
                }

                em.flush();
                em.clear();
                return new int[]{processedInChunk, _linked, _missed};
            });

            if (result != null) {
                scanned += result[0];
                linked += result[1];
                missed += result[2];
            }

            if (scanned % LOG_EVERY == 0) {
                log.info("Canonical backfill progress: scanned={}, linked={}, missed={}", scanned, linked, missed);
            }
        }

        log.info("Canonical backfill done: scanned={}, linked={}, missed={}", scanned, linked, missed);
        return new BackfillResult(scanned, linked, missed, forceRebuild);
    }

    /**
     * import直後など、特定の SoftwareInstall だけを対象に canonical link を試す。
     * - hit: software_install に cpe_vendor_id / cpe_product_id をセット
     * - vendor-only: cpe_vendor_id のみセット（product は unresolved）
     * - miss: unresolved_mappings に upsert（候補IDも埋める）
     *
     * forceRebuild=false の場合、完全リンク済み（vendor+product両方埋まっている）はスキップ。
     */
    public BackfillResult backfillForSoftwareIds(List<Long> softwareIds, boolean forceRebuild) {
        if (softwareIds == null || softwareIds.isEmpty()) {
            return new BackfillResult(0, 0, 0, forceRebuild);
        }

        List<Long> ids = softwareIds.stream()
                .filter(x -> x != null && x > 0)
                .distinct()
                .toList();

        if (ids.isEmpty()) {
            return new BackfillResult(0, 0, 0, forceRebuild);
        }

        int scanned = 0;
        int linked = 0;
        int missed = 0;

        // 同一 backfill 実行中の unresolved upsert を dedupe
        Set<String> unresolvedSeen = new HashSet<>();

        for (int offset = 0; offset < ids.size(); offset += TX_CHUNK) {
            int to = Math.min(ids.size(), offset + TX_CHUNK);
            List<Long> chunkIds = ids.subList(offset, to);

            int[] result = chunkTx.execute(status -> {
                int processedInChunk = 0;
                int _linked = 0;
                int _missed = 0;

                List<SoftwareInstall> chunk = softwareRepo.findAllById(chunkIds);

                for (SoftwareInstall s : chunk) {
                    if (s == null) continue;

                    boolean fullyLinked = (s.getCpeVendorId() != null && s.getCpeProductId() != null);
                    if (fullyLinked && !forceRebuild) {
                        processedInChunk++;
                        continue;
                    }

                    var res = linker.resolve(s);

                    String vendorIn = coalesceNullable(s.getVendorRaw(), s.getVendor());
                    String productIn = coalesceNullable(s.getProductRaw(), s.getProduct());
                    String versionIn = coalesceNullable(s.getVersionRaw(), s.getVersion());
                    String sourceIn = safeString(s.getSource());

                    if (res.hit() && !s.isCanonicalLinkDisabled()) {
                        s.linkCanonical(res.vendorId(), res.productId());
                        _linked++;
                    } else if (res.vendorId() != null) {
                        s.linkCanonical(res.vendorId(), null);
                        _linked++;

                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                        _missed++;
                    } else {
                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                        _missed++;
                    }

                    processedInChunk++;

                    if (processedInChunk % FLUSH_EVERY == 0) {
                        em.flush();
                        em.clear();
                    }
                }

                em.flush();
                em.clear();
                return new int[]{processedInChunk, _linked, _missed};
            });

            if (result != null) {
                scanned += result[0];
                linked += result[1];
                missed += result[2];
            }
        }

        log.info("Canonical backfill (by ids) done: scanned={}, linked={}, missed={}, forceRebuild={}",
                scanned, linked, missed, forceRebuild);

        return new BackfillResult(scanned, linked, missed, forceRebuild);
    }

    public BackfillResult backfillForSoftwareIds(List<Long> softwareIds) {
        return backfillForSoftwareIds(softwareIds, false);
    }

    public record BackfillResult(int scanned, int linked, int missed, boolean forceRebuild) {
    }

    // =========================================================
    // UnresolvedMapping upsert（候補IDも埋める）
    // =========================================================
    private void upsertUnresolvedMapping(String source, String vendorRaw, String productRaw, String versionRaw) {
        String v = normalizeNullable(vendorRaw);
        String p = normalizeNullable(productRaw);
        String ver = normalizeNullable(versionRaw);
        String src = safeString(source);

        if (v == null || p == null) return;

        LocalDateTime now = LocalDateTime.now();

        Optional<UnresolvedMapping> existing =
                unresolvedMappingRepository.findTopByVendorRawAndProductRaw(v, p);

        if (existing.isPresent()) {
            UnresolvedMapping um = existing.get();
            um.setLastSeenAt(now);

            um.setSource(src);
            um.setVersionRaw(ver);

            if (isBlank(um.getNormalizedVendor())) {
                um.setNormalizedVendor(normalizeVendorForAlias(v));
            }
            if (isBlank(um.getNormalizedProduct())) {
                um.setNormalizedProduct(normalizeProductForAlias(p));
            }

            if (isBlank(um.getCandidateVendorIds()) || isBlank(um.getCandidateProductIds())) {
                fillCandidatesIfPossible(um);
            }

            unresolvedMappingRepository.save(um);
            return;
        }

        UnresolvedMapping um = UnresolvedMapping.create(src, v, p, ver);

        um.setNormalizedVendor(normalizeVendorForAlias(v));
        um.setNormalizedProduct(normalizeProductForAlias(p));

        fillCandidatesIfPossible(um);

        unresolvedMappingRepository.save(um);
    }

    private boolean shouldUpsertUnresolved(Set<String> unresolvedSeen, String vendorRaw, String productRaw) {
        String key = unresolvedKey(vendorRaw, productRaw);
        if (key == null) return false;
        return unresolvedSeen.add(key);
    }

    private String unresolvedKey(String vendorRaw, String productRaw) {
        String v = normalizeNullable(vendorRaw);
        String p = normalizeNullable(productRaw);
        if (v == null || p == null) return null;
        return v + "\u0000" + p;
    }

    private void fillCandidatesIfPossible(UnresolvedMapping um) {
        String vn = normalizeNullable(um.getNormalizedVendor());
        String pn = normalizeNullable(um.getNormalizedProduct());

        List<CpeVendor> vCands = List.of();
        if (vn != null) {
            vCands = cpeVendorRepository.findTop20ByNameNormStartingWithOrderByNameNormAsc(vn);
        }
        um.setCandidateVendorIds(encodeVendors(vCands));

        if (pn != null && vCands.size() == 1) {
            Long vendorId = vCands.get(0).getId();
            List<CpeProduct> pCands =
                    cpeProductRepository.findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(vendorId, pn);
            um.setCandidateProductIds(encodeProducts(pCands));
        } else {
            if (isBlank(um.getCandidateProductIds())) {
                um.setCandidateProductIds(null);
            }
        }
    }

    private String normalizeVendorForAlias(String vendor) {
        return normalizer.normalizeVendor(vendor);
    }

    private String normalizeProductForAlias(String product) {
        return normalizer.normalizeProduct(product);
    }

    /**
     * Persist only IDs, e.g. "97,11961,8623".
     * (No ":nameNorm" to avoid column overflow and long-tail strings.)
     */
    private static String encodeVendors(List<CpeVendor> vendors) {
        if (vendors == null || vendors.isEmpty()) return null;
        return vendors.stream()
                .limit(CAND_LIMIT)
                .map(v -> String.valueOf(v.getId()))
                .collect(Collectors.joining(","));
    }

    /**
     * Persist only IDs, e.g. "123,456".
     */
    private static String encodeProducts(List<CpeProduct> products) {
        if (products == null || products.isEmpty()) return null;
        return products.stream()
                .limit(CAND_LIMIT)
                .map(p -> String.valueOf(p.getId()))
                .collect(Collectors.joining(","));
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    private static String safeString(String s) {
        String t = normalizeNullable(s);
        return t == null ? "UNKNOWN" : t;
    }

    private static String coalesceNullable(String a, String b) {
        String x = normalizeNullable(a);
        if (x != null) return x;
        return normalizeNullable(b);
    }
}