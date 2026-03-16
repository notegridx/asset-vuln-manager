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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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
        long startNanos = System.nanoTime();

        int scanned = 0;

        // backward-compatible result fields
        int linked = 0;
        int missed = 0;

        // detailed logging
        int fullyLinked = 0;
        int vendorOnly = 0;
        int pureMiss = 0;

        List<SoftwareInstall> all = forceRebuild
                ? softwareRepo.findAll()
                : softwareRepo.findNeedsCanonicalLink();

        // Dedupe unresolved upsert within the same backfill run
        Set<String> unresolvedSeen = new HashSet<>();

        // Cache resolve results within the same run
        Map<String, CachedResolveResult> resolveCache = new HashMap<>();

        for (int offset = 0; offset < all.size() && scanned < safeMax; offset += TX_CHUNK) {
            int to = Math.min(all.size(), offset + TX_CHUNK);
            List<SoftwareInstall> chunk = all.subList(offset, to);

            int remaining = safeMax - scanned;

            int[] result = chunkTx.execute(status -> {
                int processedInChunk = 0;

                // backward-compatible result fields
                int _linked = 0;
                int _missed = 0;

                // detailed logging
                int _fullyLinked = 0;
                int _vendorOnly = 0;
                int _pureMiss = 0;

                for (SoftwareInstall s : chunk) {
                    if (processedInChunk >= remaining) break;

                    boolean alreadyFullyLinked = (s.getCpeVendorId() != null && s.getCpeProductId() != null);
                    if (alreadyFullyLinked && !forceRebuild) {
                        processedInChunk++;
                        continue;
                    }

                    CachedResolveResult res = resolveWithCache(resolveCache, s);

                    String vendorIn = coalesceNullable(s.getVendorRaw(), s.getVendor());
                    String productIn = coalesceNullable(s.getProductRaw(), s.getProduct());
                    String versionIn = coalesceNullable(s.getVersionRaw(), s.getVersion());
                    String sourceIn = safeString(s.getSource());

                    if (res.hit() && !s.isCanonicalLinkDisabled()) {
                        s.linkCanonical(res.vendorId(), res.productId());

                        _linked++;
                        _fullyLinked++;
                    } else if (res.vendorId() != null) {
                        // Fill vendor-only; product stays unresolved
                        s.linkCanonical(res.vendorId(), null);

                        _linked++;
                        _missed++;
                        _vendorOnly++;

                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                    } else {
                        _missed++;
                        _pureMiss++;

                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                    }

                    processedInChunk++;

                    if (processedInChunk % FLUSH_EVERY == 0) {
                        em.flush();
                        em.clear();
                    }
                }

                em.flush();
                em.clear();
                return new int[]{processedInChunk, _linked, _missed, _fullyLinked, _vendorOnly, _pureMiss};
            });

            if (result != null) {
                scanned += result[0];

                linked += result[1];
                missed += result[2];

                fullyLinked += result[3];
                vendorOnly += result[4];
                pureMiss += result[5];
            }

            if (scanned > 0 && scanned % LOG_EVERY == 0) {
                long elapsedMs = elapsedMs(startNanos);
                String rowsPerSec = formatRowsPerSec(scanned, elapsedMs);

                log.info(
                        "Canonical backfill progress: scanned={}, linked={}, missed={}, fullyLinked={}, vendorOnly={}, pureMiss={}, elapsedMs={}, rowsPerSec={}",
                        scanned, linked, missed, fullyLinked, vendorOnly, pureMiss, elapsedMs, rowsPerSec
                );
            }
        }

        long elapsedMs = elapsedMs(startNanos);
        String elapsedSec = formatElapsedSec(elapsedMs);
        String rowsPerSec = formatRowsPerSec(scanned, elapsedMs);

        log.info(
                "Canonical backfill done: scanned={}, linked={}, missed={}, fullyLinked={}, vendorOnly={}, pureMiss={}, elapsedMs={}, elapsedSec={}, rowsPerSec={}",
                scanned, linked, missed, fullyLinked, vendorOnly, pureMiss, elapsedMs, elapsedSec, rowsPerSec
        );

        return new BackfillResult(scanned, linked, missed, forceRebuild);
    }

    /**
     * Try canonical linking only for the given SoftwareInstall IDs, e.g. right after import.
     * - hit: set cpe_vendor_id / cpe_product_id on software_install
     * - vendor-only: set only cpe_vendor_id (product stays unresolved)
     * - miss: upsert into unresolved_mappings (and fill candidate IDs)
     *
     * When forceRebuild=false, fully linked rows are skipped.
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

        long startNanos = System.nanoTime();

        int scanned = 0;

        // backward-compatible result fields
        int linked = 0;
        int missed = 0;

        // detailed logging
        int fullyLinked = 0;
        int vendorOnly = 0;
        int pureMiss = 0;

        // Dedupe unresolved upsert within the same backfill run
        Set<String> unresolvedSeen = new HashSet<>();

        // Cache resolve results within the same run
        Map<String, CachedResolveResult> resolveCache = new HashMap<>();

        for (int offset = 0; offset < ids.size(); offset += TX_CHUNK) {
            int to = Math.min(ids.size(), offset + TX_CHUNK);
            List<Long> chunkIds = ids.subList(offset, to);

            int[] result = chunkTx.execute(status -> {
                int processedInChunk = 0;

                // backward-compatible result fields
                int _linked = 0;
                int _missed = 0;

                // detailed logging
                int _fullyLinked = 0;
                int _vendorOnly = 0;
                int _pureMiss = 0;

                List<SoftwareInstall> chunk = softwareRepo.findAllById(chunkIds);

                for (SoftwareInstall s : chunk) {
                    if (s == null) continue;

                    boolean alreadyFullyLinked = (s.getCpeVendorId() != null && s.getCpeProductId() != null);
                    if (alreadyFullyLinked && !forceRebuild) {
                        processedInChunk++;
                        continue;
                    }

                    CachedResolveResult res = resolveWithCache(resolveCache, s);

                    String vendorIn = coalesceNullable(s.getVendorRaw(), s.getVendor());
                    String productIn = coalesceNullable(s.getProductRaw(), s.getProduct());
                    String versionIn = coalesceNullable(s.getVersionRaw(), s.getVersion());
                    String sourceIn = safeString(s.getSource());

                    if (res.hit() && !s.isCanonicalLinkDisabled()) {
                        s.linkCanonical(res.vendorId(), res.productId());

                        _linked++;
                        _fullyLinked++;
                    } else if (res.vendorId() != null) {
                        s.linkCanonical(res.vendorId(), null);

                        _linked++;
                        _missed++;
                        _vendorOnly++;

                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                    } else {
                        _missed++;
                        _pureMiss++;

                        if (shouldUpsertUnresolved(unresolvedSeen, vendorIn, productIn)) {
                            upsertUnresolvedMapping(sourceIn, vendorIn, productIn, versionIn);
                        }
                    }

                    processedInChunk++;

                    if (processedInChunk % FLUSH_EVERY == 0) {
                        em.flush();
                        em.clear();
                    }
                }

                em.flush();
                em.clear();
                return new int[]{processedInChunk, _linked, _missed, _fullyLinked, _vendorOnly, _pureMiss};
            });

            if (result != null) {
                scanned += result[0];

                linked += result[1];
                missed += result[2];

                fullyLinked += result[3];
                vendorOnly += result[4];
                pureMiss += result[5];
            }
        }

        long elapsedMs = elapsedMs(startNanos);
        String elapsedSec = formatElapsedSec(elapsedMs);
        String rowsPerSec = formatRowsPerSec(scanned, elapsedMs);

        log.info(
                "Canonical backfill (by ids) done: scanned={}, linked={}, missed={}, fullyLinked={}, vendorOnly={}, pureMiss={}, forceRebuild={}, elapsedMs={}, elapsedSec={}, rowsPerSec={}",
                scanned, linked, missed, fullyLinked, vendorOnly, pureMiss, forceRebuild, elapsedMs, elapsedSec, rowsPerSec
        );

        return new BackfillResult(scanned, linked, missed, forceRebuild);
    }

    public BackfillResult backfillForSoftwareIds(List<Long> softwareIds) {
        return backfillForSoftwareIds(softwareIds, false);
    }

    public record BackfillResult(int scanned, int linked, int missed, boolean forceRebuild) {
    }

    private CachedResolveResult resolveWithCache(Map<String, CachedResolveResult> resolveCache, SoftwareInstall s) {
        String key = buildResolveCacheKey(s);
        return resolveCache.computeIfAbsent(key, k -> {
            var res = linker.resolve(s);
            return new CachedResolveResult(res.hit(), res.vendorId(), res.productId());
        });
    }

    private String buildResolveCacheKey(SoftwareInstall s) {
        return safePart(s.getSource()) + "\u0000"
                + safePart(s.getVendorRaw()) + "\u0000"
                + safePart(s.getVendor()) + "\u0000"
                + safePart(s.getProductRaw()) + "\u0000"
                + safePart(s.getProduct()) + "\u0000"
                + safePart(s.getVersionRaw()) + "\u0000"
                + safePart(s.getVersion()) + "\u0000"
                + safePart(s.getNormalizedVendor()) + "\u0000"
                + safePart(s.getNormalizedProduct());
    }

    // =========================================================
    // UnresolvedMapping upsert (including candidate IDs)
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

    private static long elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    private static String formatElapsedSec(long elapsedMs) {
        return String.format("%.3f", elapsedMs / 1000.0);
    }

    private static String formatRowsPerSec(int rows, long elapsedMs) {
        if (elapsedMs <= 0L) {
            return rows > 0 ? String.valueOf(rows) : "0.0";
        }
        double rowsPerSec = rows / (elapsedMs / 1000.0);
        return String.format("%.1f", rowsPerSec);
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

    private static String safePart(String s) {
        return s == null ? "" : s;
    }

    private record CachedResolveResult(boolean hit, Long vendorId, Long productId) {
    }
}