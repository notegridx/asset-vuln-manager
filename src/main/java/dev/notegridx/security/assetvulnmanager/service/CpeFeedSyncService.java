package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeSyncState;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeFeedMetaParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeNameParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCpeFeedClient;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeSyncStateRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.*;
import java.util.zip.GZIPInputStream;


@Service
public class CpeFeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(CpeFeedSyncService.class);

    private static final String FEED_NAME = "nvd-cpe-dict";

    // tune
    private static final int LOG_EVERY = 10_000;
    private static final int FLUSH_EVERY = 5_000;
    private static final int TX_CHUNK = 10_000;

    // caches (LRU)
    private final Map<String, Long> vendorIdCache = new LruMap<>(200_000);
    private final Map<Long, Set<String>> productKeyCache = new LruMap<>(200_000);

    private final NvdCpeFeedClient feedClient;

    private final CpeVendorRepository vendorRepository;
    private final CpeProductRepository productRepository;
    private final CpeSyncStateRepository syncStateRepository;

    private final EntityManager em;
    private final TransactionTemplate chunkTx;

    private final CpeFeedMetaParser metaParser = new CpeFeedMetaParser();
    private final CpeNameParser cpeNameParser = new CpeNameParser();
    private final JsonFactory jsonFactory = new JsonFactory();

    public CpeFeedSyncService(
            NvdCpeFeedClient feedClient,
            CpeVendorRepository vendorRepository,
            CpeProductRepository productRepository,
            CpeSyncStateRepository syncStateRepository,
            EntityManager em,
            PlatformTransactionManager txManager
    ) {
        this.feedClient = feedClient;
        this.vendorRepository = vendorRepository;
        this.productRepository = productRepository;
        this.syncStateRepository = syncStateRepository;
        this.em = em;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.chunkTx = tt;
    }

    public SyncResult sync(boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        // 1) META fetch
        CpeFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(metaParser);

        // 2) compare with sync_state
        CpeSyncState state = syncStateRepository.findByFeedName(FEED_NAME)
                .orElseGet(() -> new CpeSyncState(FEED_NAME));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CPE feed sync skipped (meta unchanged). feedName={}, sha256={}, lastModified={}, size={}",
                    FEED_NAME, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skipped(meta.sha256(), meta.lastModified(), meta.size());
        }

        // 3) download gz
        byte[] gz = feedClient.downloadGz();
        log.info("CPE feed downloaded: bytes={}, force={}, cap={}", gz.length, force, safeMax);

        // 4) parse & upsert with chunked transactions
        ParseUpsertResult r = parseAndUpsertChunked(gz, safeMax);

        // 5) update sync state
        state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
        syncStateRepository.save(state);

        log.info("CPE feed sync done: vendorsInserted={}, productsInserted={}, cpeParsed={}, vendorCache={}, productCache={}",
                r.vendorsInserted, r.productsInserted, r.cpeParsed, vendorIdCache.size(), productKeyCache.size());

        return SyncResult.executed(r.vendorsInserted, r.productsInserted, r.cpeParsed,
                meta.sha256(), meta.lastModified(), meta.size());
    }

    private ParseUpsertResult parseAndUpsertChunked(byte[] gzBytes, int maxItems) throws IOException {
        final int[] vendorsInserted = {0};
        final int[] productsInserted = {0};
        final int[] parsed = {0};

        try (InputStream bin = new ByteArrayInputStream(gzBytes);
             GZIPInputStream gin = new GZIPInputStream(bin);
             JsonParser p = jsonFactory.createParser(gin)) {

            // streaming loop
            List<CpeNameParser.VendorProduct> buffer = new ArrayList<>(TX_CHUNK);

            while (p.nextToken() != null) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (!(v == JsonToken.VALUE_STRING && "cpe23Uri".equals(field))) continue;

                String cpe23 = p.getValueAsString();
                parsed[0]++;
                if (parsed[0] > maxItems) break;

                Optional<CpeNameParser.VendorProduct> vpOpt = cpeNameParser.parseVendorProduct(cpe23);
                if (vpOpt.isEmpty()) continue;

                buffer.add(vpOpt.get());

                if (buffer.size() >= TX_CHUNK) {
                    List<CpeNameParser.VendorProduct> chunk = new ArrayList<>(buffer);
                    buffer.clear();

                    chunkTx.execute(status -> {
                        var r = upsertChunk(chunk, parsed[0]);
                        vendorsInserted[0] += r.vendorsInserted;
                        productsInserted[0] += r.productsInserted;
                        return null;
                    });
                }

                if (parsed[0] % LOG_EVERY == 0) {
                    log.info("CPE sync progress: parsed={}, vendorsInsertedSoFar={}, productsInsertedSoFar={}",
                            parsed[0], vendorsInserted[0], productsInserted[0]);
                }
            }

            // tail
            if (!buffer.isEmpty()) {
                List<CpeNameParser.VendorProduct> chunk = new ArrayList<>(buffer);
                buffer.clear();

                chunkTx.execute(status -> {
                    var r = upsertChunk(chunk, parsed[0]);
                    vendorsInserted[0] += r.vendorsInserted;
                    productsInserted[0] += r.productsInserted;
                    return null;
                });
            }
        }

        return new ParseUpsertResult(vendorsInserted[0], productsInserted[0], parsed[0]);
    }

    private ChunkResult upsertChunk(List<CpeNameParser.VendorProduct> chunk, int parsedSoFar) {
        int vIns = 0;
        int pIns = 0;

        int processed = 0;
        for (var vp : chunk) {
            processed++;

            Long vendorId = ensureVendorId(vp.vendor());
            if (vendorId == null) continue;

            boolean productInserted = ensureProduct(vendorId, vp.product());
            if (productInserted) pIns++;

            // periodic flush/clear to avoid persistence context bloat
            if (processed % FLUSH_EVERY == 0) {
                em.flush();
                em.clear();
            }
        }

        // final flush for this chunk
        em.flush();
        em.clear();

        if (parsedSoFar % LOG_EVERY == 0) {
            log.info("CPE sync chunk done: parsedSoFar={}, vendorsInsertedChunk={}, productsInsertedChunk={}",
                    parsedSoFar, vIns, pIns);
        }

        return new ChunkResult(vIns, pIns);
    }

    private Long ensureVendorId(String vendorKey) {
        if (vendorKey == null || vendorKey.isBlank()) return null;

        Long cached = vendorIdCache.get(vendorKey);
        if (cached != null) return cached;

        // 1) try DB read
        var existing = vendorRepository.findByNameNorm(vendorKey).orElse(null);
        if (existing != null) {
            vendorIdCache.put(vendorKey, existing.getId());
            return existing.getId();
        }

        // 2) try insert, race-safe with unique + exception
        try {
            CpeVendor saved = vendorRepository.save(new CpeVendor(vendorKey, null));
            Long id = saved.getId();
            if (id != null) vendorIdCache.put(vendorKey, id);
            return id;
        } catch (DataIntegrityViolationException dup) {
            // someone inserted concurrently; re-read
            var ex2 = vendorRepository.findByNameNorm(vendorKey).orElse(null);
            if (ex2 != null) {
                vendorIdCache.put(vendorKey, ex2.getId());
                return ex2.getId();
            }
            return null;
        }
    }

    private boolean ensureProduct(Long vendorId, String productKey) {
        if (vendorId == null) return false;
        if (productKey == null || productKey.isBlank()) return false;

        // cache: vendorId -> known products
        Set<String> known = productKeyCache.computeIfAbsent(vendorId, k -> new HashSet<>());
        if (known.contains(productKey)) return false;

        // fast path: if DB says it exists, mark cache and return
        if (productRepository.existsByVendorIdAndNameNorm(vendorId, productKey)) {
            known.add(productKey);
            return false;
        }

        // insert with exception-based upsert
        try {
            // attach vendor reference (no extra SELECT)
            CpeVendor vendorRef = em.getReference(CpeVendor.class, vendorId);
            productRepository.save(new CpeProduct(vendorRef, productKey, null));
            known.add(productKey);
            return true;
        } catch (DataIntegrityViolationException dup) {
            // inserted by someone else / earlier in tx: treat as exists
            known.add(productKey);
            return false;
        }
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    private record ChunkResult(int vendorsInserted, int productsInserted) {
    }

    private record ParseUpsertResult(int vendorsInserted, int productsInserted, int cpeParsed) {
    }

    public record SyncResult(
            boolean skipped,
            int vendorsInserted,
            int productsInserted,
            int cpeParsed,
            String metaSha256,
            String metaLastModified,
            Long metaSize
    ) {
        public static SyncResult skipped(String sha256, String lastModified, Long size) {
            return new SyncResult(true, 0, 0, 0, sha256, lastModified, size);
        }

        public static SyncResult executed(int vIns, int pIns, int parsed, String sha256, String lastModified, Long size) {
            return new SyncResult(false, vIns, pIns, parsed, sha256, lastModified, size);
        }
    }

    static final class LruMap<K, V> extends LinkedHashMap<K, V> {
        private final int max;

        LruMap(int max) {
            super(16, 0.75f, true);
            this.max = max;
        }

        @Override
        protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
            return size() > max;
        }
    }
}
