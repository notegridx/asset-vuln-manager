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
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
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

    // peek-log safety
    private static final int PEEK_KEYS_LIMIT = 80;

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

    // IMPORTANT: prevent JsonParser.close() from closing TarArchiveInputStream
    private final JsonFactory jsonFactory;

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

        JsonFactory jf = new JsonFactory();
        jf.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
        this.jsonFactory = jf;
    }

    public SyncResult sync(boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        // 1) META fetch (small)
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

        // 3) download tar.gz -> temp file (streaming, no byte[])
        Path tmp = null;
        long bytes = 0;
        try {
            tmp = feedClient.downloadTarGzToTempFile();
            bytes = Files.size(tmp);
            log.info("CPE feed downloaded to temp: file={}, bytes={}, force={}, cap={}", tmp, bytes, force, safeMax);

            // 4) parse & upsert with chunked transactions
            try (InputStream in = Files.newInputStream(tmp)) {
                ParseUpsertResult r = parseAndUpsertTarGzChunked(in, safeMax);

                // 5) update sync state
                state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
                syncStateRepository.save(state);

                log.info("CPE feed sync done: vendorsInserted={}, productsInserted={}, cpeParsed={}, vendorCache={}, productCache={}",
                        r.vendorsInserted, r.productsInserted, r.cpeParsed, vendorIdCache.size(), productKeyCache.size());

                return SyncResult.executed(r.vendorsInserted, r.productsInserted, r.cpeParsed,
                        meta.sha256(), meta.lastModified(), meta.size());
            }
        } finally {
            if (tmp != null) {
                try {
                    Files.deleteIfExists(tmp);
                } catch (Exception e) {
                    log.warn("Failed to delete temp file (ignored). file={}, err={}", tmp, safeMsg(e));
                }
            }
        }
    }

    /**
     * tar.gz -> (GZIPInputStream) -> (TarArchiveInputStream)
     * For first tar entry only:
     * - readAllEntryBytes (cannot re-read stream)
     * - peek keys(depth<=2, limit<=80) and log
     * - parse from byte[] (ByteArrayInputStream)
     * Remaining entries:
     * - parse directly from tar stream
     */
    private ParseUpsertResult parseAndUpsertTarGzChunked(InputStream tarGzStream, int maxItems) throws IOException {
        final int[] vendorsInserted = {0};
        final int[] productsInserted = {0};
        final int[] parsed = {0};

        // streaming buffer
        List<CpeNameParser.VendorProduct> buffer = new ArrayList<>(TX_CHUNK);

        try (GZIPInputStream gin = new GZIPInputStream(tarGzStream);
             TarArchiveInputStream tin = new TarArchiveInputStream(gin)) {

            boolean firstEntryPeeked = false;

            TarArchiveEntry entry;
            while ((entry = tin.getNextTarEntry()) != null) {
                if (!entry.isFile()) continue;

                String entryName = entry.getName();
                log.info("CPE tar entry: name={}, size={}", entryName, entry.getSize());

                if (!firstEntryPeeked) {
                    // 1st entry: read all bytes, peek keys, then parse from byte[]
                    byte[] entryBytes = readAllEntryBytes(tin);

                    Set<String> keys = collectKeysDepthLe2(entryBytes, PEEK_KEYS_LIMIT);
                    log.info("CPE entry peek keys (depth<=2, limit={}): {}", PEEK_KEYS_LIMIT, keys);

                    parseCpeJsonStream(new ByteArrayInputStream(entryBytes), maxItems, parsed, buffer, vendorsInserted, productsInserted);
                    firstEntryPeeked = true;

                } else {
                    // subsequent entries: parse directly from tar stream
                    parseCpeJsonStream(tin, maxItems, parsed, buffer, vendorsInserted, productsInserted);
                }

                if (parsed[0] >= maxItems) break;
            }

            // tail flush
            if (!buffer.isEmpty() && parsed[0] > 0) {
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

    /**
     * Parse one JSON stream (one tar entry) with Jackson streaming,
     * extracting CPE name strings.
     *
     * Feed/API2 often uses "cpeName" (not "cpe23Uri").
     * We accept both keys and only count valid "cpe:2.3:" strings.
     *
     * NOTE: JsonFactory is configured with AUTO_CLOSE_SOURCE disabled,
     * so closing parser won't close underlying TarArchiveInputStream.
     */
    private void parseCpeJsonStream(
            InputStream jsonStream,
            int maxItems,
            int[] parsed,
            List<CpeNameParser.VendorProduct> buffer,
            int[] vendorsInserted,
            int[] productsInserted
    ) throws IOException {

        try (JsonParser p = jsonFactory.createParser(jsonStream)) {

            while (p.nextToken() != null) {

                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (v != JsonToken.VALUE_STRING) continue;

                boolean isCpeField = "cpe23Uri".equals(field) || "cpeName".equals(field);
                if (!isCpeField) continue;

                String cpe = p.getValueAsString();
                if (cpe == null || !cpe.startsWith("cpe:2.3:")) continue;

                parsed[0]++;

                if (parsed[0] > maxItems) break;

                Optional<CpeNameParser.VendorProduct> vpOpt = cpeNameParser.parseVendorProduct(cpe);
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
        }
    }

    /**
     * Collect FIELD_NAME keys for a "peek" log, limited depth <= 2.
     * Implementation is best-effort, safe, and bounded.
     */
    private Set<String> collectKeysDepthLe2(byte[] jsonBytes, int limit) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (jsonBytes == null || jsonBytes.length == 0) return out;

        try (JsonParser p = jsonFactory.createParser(new ByteArrayInputStream(jsonBytes))) {
            int objectDepth = 0;
            while (p.nextToken() != null && out.size() < limit) {
                JsonToken t = p.currentToken();

                if (t == JsonToken.START_OBJECT) {
                    objectDepth++;
                } else if (t == JsonToken.END_OBJECT) {
                    objectDepth = Math.max(0, objectDepth - 1);
                } else if (t == JsonToken.FIELD_NAME) {
                    // depth<=2 means root object (1) and its direct nested object (2)
                    if (objectDepth <= 2) out.add(p.currentName());
                }
            }
        } catch (Exception e) {
            log.warn("CPE peek keys failed (ignored). err={}", safeMsg(e));
        }

        return out;
    }

    /**
     * Reads current tar entry bytes fully from TarArchiveInputStream.
     * (Required because tar entry cannot be rewound.)
     */
    private static byte[] readAllEntryBytes(TarArchiveInputStream tin) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1024 * 1024);
        byte[] buf = new byte[8192];
        int n;
        while ((n = tin.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }

    private ChunkResult upsertChunk(List<CpeNameParser.VendorProduct> chunk, int parsedSoFar) {
        int vIns = 0;
        int pIns = 0;

        int processed = 0;
        for (var vp : chunk) {
            processed++;

            VendorEnsureResult vr = ensureVendor(vp.vendor());
            Long vendorId = vr.id();
            if (vendorId == null) continue;

            if (vr.inserted) vIns++;

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

    /**
     * Ensure vendor exists and return:
     * - id
     * - whether this call inserted a new row
     */
    private VendorEnsureResult ensureVendor(String vendorKey) {
        if (vendorKey == null || vendorKey.isBlank()) return VendorEnsureResult.none();

        Long cached = vendorIdCache.get(vendorKey);
        if (cached != null) return VendorEnsureResult.existing(cached);

        // 1) try DB read
        var existing = vendorRepository.findByNameNorm(vendorKey).orElse(null);
        if (existing != null) {
            vendorIdCache.put(vendorKey, existing.getId());
            return VendorEnsureResult.existing(existing.getId());
        }

        // 2) try insert, race-safe with unique + exception
        try {
            CpeVendor saved = vendorRepository.save(new CpeVendor(vendorKey, null));
            Long id = saved.getId();
            if (id != null) vendorIdCache.put(vendorKey, id);
            return (id == null) ? VendorEnsureResult.none() : VendorEnsureResult.inserted(id);

        } catch (DataIntegrityViolationException dup) {
            // someone inserted concurrently; re-read
            var ex2 = vendorRepository.findByNameNorm(vendorKey).orElse(null);
            if (ex2 != null) {
                vendorIdCache.put(vendorKey, ex2.getId());
                return VendorEnsureResult.existing(ex2.getId());
            }
            return VendorEnsureResult.none();
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

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        return (m == null) ? t.getClass().getSimpleName() : m;
    }

    private record VendorEnsureResult(Long id, boolean inserted) {
        static VendorEnsureResult inserted(Long id) { return new VendorEnsureResult(id, true); }
        static VendorEnsureResult existing(Long id) { return new VendorEnsureResult(id, false); }
        static VendorEnsureResult none() { return new VendorEnsureResult(null, false); }
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