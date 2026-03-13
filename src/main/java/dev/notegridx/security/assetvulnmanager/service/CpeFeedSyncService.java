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
import dev.notegridx.security.assetvulnmanager.domain.enums.CpeSyncSourceMode;
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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
    private static final boolean ENABLE_FIRST_ENTRY_PEEK_LOG = false;

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
        long startedAtNs = System.nanoTime();

        CpeFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(metaParser);

        CpeSyncState state = syncStateRepository.findByFeedName(FEED_NAME)
                .orElseGet(() -> new CpeSyncState(FEED_NAME));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CPE feed sync skipped (meta unchanged). feedName={}, sha256={}, lastModified={}, size={}",
                    FEED_NAME, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skippedDownload(meta.sha256(), meta.lastModified(), meta.size());
        }

        Path tmp = null;
        long bytes = 0L;
        try {
            tmp = feedClient.downloadTarGzToTempFile();
            bytes = Files.size(tmp);
            log.info("CPE feed downloaded to temp: file={}, bytes={}, force={}, cap={}", tmp, bytes, force, safeMax);

            try (InputStream in = Files.newInputStream(tmp)) {
                ParseUpsertResult r = parseAndUpsertTarGzChunked(in, safeMax);

                state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
                syncStateRepository.save(state);

                long elapsedMs = elapsedMs(startedAtNs);
                double elapsedSec = elapsedMs / 1000.0d;
                double rowsPerSec = elapsedSec <= 0.0d ? r.cpeParsed : (r.cpeParsed / elapsedSec);

                log.info(
                        "CPE feed sync done: vendorsInserted={}, productsInserted={}, cpeParsed={}, elapsedMs={}, elapsedSec={}, rowsPerSec={}, vendorCache={}, productCache={}",
                        r.vendorsInserted,
                        r.productsInserted,
                        r.cpeParsed,
                        elapsedMs,
                        String.format(Locale.ROOT, "%.3f", elapsedSec),
                        String.format(Locale.ROOT, "%.2f", rowsPerSec),
                        vendorIdCache.size(),
                        productKeyCache.size()
                );

                return SyncResult.executedDownload(
                        r.vendorsInserted,
                        r.productsInserted,
                        r.cpeParsed,
                        elapsedMs,
                        elapsedSec,
                        rowsPerSec,
                        meta.sha256(),
                        meta.lastModified(),
                        meta.size()
                );
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

    public SyncResult syncFromUploadedTarGz(InputStream tarGzStream, String originalFilename, int maxItems) throws IOException {
        if (tarGzStream == null) {
            throw new IllegalArgumentException("Uploaded file stream is empty.");
        }

        int safeMax = clamp(maxItems, 1, 5_000_000);
        long startedAtNs = System.nanoTime();

        try (InputStream in = tarGzStream) {
            ParseUpsertResult r = parseAndUpsertTarGzChunked(in, safeMax);

            long elapsedMs = elapsedMs(startedAtNs);
            double elapsedSec = elapsedMs / 1000.0d;
            double rowsPerSec = elapsedSec <= 0.0d ? r.cpeParsed : (r.cpeParsed / elapsedSec);

            log.info(
                    "CPE upload sync done: filename={}, vendorsInserted={}, productsInserted={}, cpeParsed={}, elapsedMs={}, elapsedSec={}, rowsPerSec={}, vendorCache={}, productCache={}",
                    originalFilename,
                    r.vendorsInserted,
                    r.productsInserted,
                    r.cpeParsed,
                    elapsedMs,
                    String.format(Locale.ROOT, "%.3f", elapsedSec),
                    String.format(Locale.ROOT, "%.2f", rowsPerSec),
                    vendorIdCache.size(),
                    productKeyCache.size()
            );

            return SyncResult.executedUpload(
                    r.vendorsInserted,
                    r.productsInserted,
                    r.cpeParsed,
                    elapsedMs,
                    elapsedSec,
                    rowsPerSec,
                    originalFilename
            );
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException(
                    "Uploaded file is not a valid CPE Dictionary .tar.gz archive: " + safeMsg(ex), ex
            );
        }
    }

    private ParseUpsertResult parseAndUpsertTarGzChunked(InputStream tarGzStream, int maxItems) throws IOException {
        final int[] vendorsInserted = {0};
        final int[] productsInserted = {0};
        final int[] parsed = {0};

        List<CpeNameParser.VendorProduct> buffer = new ArrayList<>(TX_CHUNK);

        try (GZIPInputStream gin = new GZIPInputStream(tarGzStream);
             TarArchiveInputStream tin = new TarArchiveInputStream(gin)) {

            boolean firstEntryPeeked = false;

            TarArchiveEntry entry;
            while ((entry = tin.getNextTarEntry()) != null) {
                if (!entry.isFile()) {
                    continue;
                }

                String entryName = entry.getName();
                log.info("CPE tar entry: name={}, size={}", entryName, entry.getSize());

                if (!firstEntryPeeked && ENABLE_FIRST_ENTRY_PEEK_LOG) {
                    byte[] entryBytes = readAllEntryBytes(tin);

                    Set<String> keys = collectKeysDepthLe2(entryBytes, PEEK_KEYS_LIMIT);
                    log.info("CPE entry peek keys (depth<=2, limit={}): {}", PEEK_KEYS_LIMIT, keys);

                    parseCpeJsonStream(new ByteArrayInputStream(entryBytes), maxItems, parsed, buffer, vendorsInserted, productsInserted);
                    firstEntryPeeked = true;
                } else {
                    parseCpeJsonStream(tin, maxItems, parsed, buffer, vendorsInserted, productsInserted);
                    firstEntryPeeked = true;
                }

                if (parsed[0] >= maxItems) {
                    break;
                }
            }

            if (!buffer.isEmpty() && parsed[0] > 0) {
                List<CpeNameParser.VendorProduct> chunk = new ArrayList<>(buffer);
                buffer.clear();

                chunkTx.execute(status -> {
                    ChunkResult r = upsertChunk(chunk, parsed[0]);
                    vendorsInserted[0] += r.vendorsInserted;
                    productsInserted[0] += r.productsInserted;
                    return null;
                });
            }
        }

        return new ParseUpsertResult(vendorsInserted[0], productsInserted[0], parsed[0]);
    }

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

                if (p.currentToken() != JsonToken.FIELD_NAME) {
                    continue;
                }

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (v != JsonToken.VALUE_STRING) {
                    continue;
                }

                boolean isCpeField = "cpe23Uri".equals(field) || "cpeName".equals(field);
                if (!isCpeField) {
                    continue;
                }

                String cpe = p.getValueAsString();
                if (cpe == null || !cpe.startsWith("cpe:2.3:")) {
                    continue;
                }

                parsed[0]++;

                if (parsed[0] > maxItems) {
                    break;
                }

                Optional<CpeNameParser.VendorProduct> vpOpt = cpeNameParser.parseVendorProduct(cpe);
                if (vpOpt.isEmpty()) {
                    continue;
                }

                buffer.add(vpOpt.get());

                if (buffer.size() >= TX_CHUNK) {
                    List<CpeNameParser.VendorProduct> chunk = new ArrayList<>(buffer);
                    buffer.clear();

                    chunkTx.execute(status -> {
                        ChunkResult r = upsertChunk(chunk, parsed[0]);
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

    private Set<String> collectKeysDepthLe2(byte[] jsonBytes, int limit) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (jsonBytes == null || jsonBytes.length == 0) {
            return out;
        }

        try (JsonParser p = jsonFactory.createParser(new ByteArrayInputStream(jsonBytes))) {
            int objectDepth = 0;
            while (p.nextToken() != null && out.size() < limit) {
                JsonToken t = p.currentToken();

                if (t == JsonToken.START_OBJECT) {
                    objectDepth++;
                } else if (t == JsonToken.END_OBJECT) {
                    objectDepth = Math.max(0, objectDepth - 1);
                } else if (t == JsonToken.FIELD_NAME) {
                    if (objectDepth <= 2) {
                        out.add(p.currentName());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("CPE peek keys failed (ignored). err={}", safeMsg(e));
        }

        return out;
    }

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

        Map<String, VendorBucket> byVendor = new LinkedHashMap<>();

        for (CpeNameParser.VendorProduct vp : chunk) {
            if (vp == null) {
                continue;
            }

            String vendorKey = vp.vendor();
            String productKey = vp.product();

            if (vendorKey == null || vendorKey.isBlank()) {
                continue;
            }
            if (productKey == null || productKey.isBlank()) {
                continue;
            }

            VendorBucket bucket = byVendor.computeIfAbsent(vendorKey, k -> new VendorBucket());
            bucket.products.add(productKey);
        }

        int processedVendors = 0;
        for (Map.Entry<String, VendorBucket> e : byVendor.entrySet()) {
            processedVendors++;

            VendorEnsureResult vr = ensureVendor(e.getKey());
            Long vendorId = vr.id();
            if (vendorId == null) {
                continue;
            }

            if (vr.inserted) {
                vIns++;
            }

            int inserted = ensureProductsBulk(vendorId, e.getValue().products);
            pIns += inserted;

            if (processedVendors % FLUSH_EVERY == 0) {
                em.flush();
                em.clear();
            }
        }

        em.flush();
        em.clear();

        if (parsedSoFar % LOG_EVERY == 0) {
            log.info("CPE sync chunk done: parsedSoFar={}, vendorsInsertedChunk={}, productsInsertedChunk={}",
                    parsedSoFar, vIns, pIns);
        }

        return new ChunkResult(vIns, pIns);
    }

    private VendorEnsureResult ensureVendor(String vendorKey) {
        if (vendorKey == null || vendorKey.isBlank()) {
            return VendorEnsureResult.none();
        }

        Long cached = vendorIdCache.get(vendorKey);
        if (cached != null) {
            return VendorEnsureResult.existing(cached);
        }

        CpeVendor existing = vendorRepository.findByNameNorm(vendorKey).orElse(null);
        if (existing != null) {
            vendorIdCache.put(vendorKey, existing.getId());
            return VendorEnsureResult.existing(existing.getId());
        }

        try {
            CpeVendor saved = vendorRepository.save(new CpeVendor(vendorKey, null));
            Long id = saved.getId();
            if (id != null) {
                vendorIdCache.put(vendorKey, id);
            }
            return (id == null) ? VendorEnsureResult.none() : VendorEnsureResult.inserted(id);

        } catch (DataIntegrityViolationException dup) {
            CpeVendor ex2 = vendorRepository.findByNameNorm(vendorKey).orElse(null);
            if (ex2 != null) {
                vendorIdCache.put(vendorKey, ex2.getId());
                return VendorEnsureResult.existing(ex2.getId());
            }
            return VendorEnsureResult.none();
        }
    }

    private int ensureProductsBulk(Long vendorId, Collection<String> productKeys) {
        if (vendorId == null || productKeys == null || productKeys.isEmpty()) {
            return 0;
        }

        Set<String> known = productKeyCache.computeIfAbsent(vendorId, k -> new HashSet<>());

        LinkedHashSet<String> requested = new LinkedHashSet<>();
        for (String productKey : productKeys) {
            if (productKey == null || productKey.isBlank()) {
                continue;
            }
            requested.add(productKey);
        }
        if (requested.isEmpty()) {
            return 0;
        }

        List<String> unknown = new ArrayList<>();
        for (String productKey : requested) {
            if (!known.contains(productKey)) {
                unknown.add(productKey);
            }
        }
        if (unknown.isEmpty()) {
            return 0;
        }

        List<CpeProduct> existingRows = productRepository.findByVendorIdAndNameNormIn(vendorId, unknown);
        for (CpeProduct row : existingRows) {
            if (row.getNameNorm() != null) {
                known.add(row.getNameNorm());
            }
        }

        int inserted = 0;
        CpeVendor vendorRef = em.getReference(CpeVendor.class, vendorId);

        for (String productKey : unknown) {
            if (known.contains(productKey)) {
                continue;
            }

            try {
                productRepository.save(new CpeProduct(vendorRef, productKey, null));
                known.add(productKey);
                inserted++;
            } catch (DataIntegrityViolationException dup) {
                known.add(productKey);
            }
        }

        return inserted;
    }

    private static long elapsedMs(long startedAtNs) {
        return (System.nanoTime() - startedAtNs) / 1_000_000L;
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) {
            return min;
        }
        if (v > max) {
            return max;
        }
        return v;
    }

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        return (m == null) ? t.getClass().getSimpleName() : m;
    }

    private record VendorEnsureResult(Long id, boolean inserted) {
        static VendorEnsureResult inserted(Long id) {
            return new VendorEnsureResult(id, true);
        }

        static VendorEnsureResult existing(Long id) {
            return new VendorEnsureResult(id, false);
        }

        static VendorEnsureResult none() {
            return new VendorEnsureResult(null, false);
        }
    }

    private static final class VendorBucket {
        private final Set<String> products = new LinkedHashSet<>();
    }

    private record ChunkResult(int vendorsInserted, int productsInserted) {
    }

    private record ParseUpsertResult(int vendorsInserted, int productsInserted, int cpeParsed) {
    }

    public record SyncResult(
            CpeSyncSourceMode sourceMode,
            boolean skipped,
            int vendorsInserted,
            int productsInserted,
            int cpeParsed,
            long elapsedMs,
            double elapsedSec,
            double rowsPerSec,
            String sourceFilename,
            CpeSyncMeta meta
    ) {
        public SyncResult {
            if (sourceMode == null) {
                throw new IllegalArgumentException("sourceMode must not be null");
            }
            if (vendorsInserted < 0) {
                throw new IllegalArgumentException("vendorsInserted must be >= 0");
            }
            if (productsInserted < 0) {
                throw new IllegalArgumentException("productsInserted must be >= 0");
            }
            if (cpeParsed < 0) {
                throw new IllegalArgumentException("cpeParsed must be >= 0");
            }
            if (elapsedMs < 0) {
                throw new IllegalArgumentException("elapsedMs must be >= 0");
            }
            if (elapsedSec < 0) {
                throw new IllegalArgumentException("elapsedSec must be >= 0");
            }
            if (rowsPerSec < 0) {
                throw new IllegalArgumentException("rowsPerSec must be >= 0");
            }
            if (meta == null) {
                meta = new CpeSyncMeta(null, null, null);
            }
        }

        public boolean isDownload() {
            return sourceMode == CpeSyncSourceMode.DOWNLOAD;
        }

        public boolean isUpload() {
            return sourceMode == CpeSyncSourceMode.UPLOAD;
        }

        public boolean hasMeta() {
            return meta != null && !meta.isEmpty();
        }

        public String metaSha256() {
            return meta != null ? meta.sha256() : null;
        }

        public String metaLastModified() {
            return meta != null ? meta.lastModified() : null;
        }

        public Long metaSize() {
            return meta != null ? meta.size() : null;
        }

        public static SyncResult skippedDownload(String sha256, String lastModified, Long size) {
            return new SyncResult(
                    CpeSyncSourceMode.DOWNLOAD,
                    true,
                    0,
                    0,
                    0,
                    0L,
                    0.0d,
                    0.0d,
                    null,
                    new CpeSyncMeta(sha256, lastModified, size)
            );
        }

        public static SyncResult executedDownload(
                int vIns,
                int pIns,
                int parsed,
                long elapsedMs,
                double elapsedSec,
                double rowsPerSec,
                String sha256,
                String lastModified,
                Long size
        ) {
            return new SyncResult(
                    CpeSyncSourceMode.DOWNLOAD,
                    false,
                    vIns,
                    pIns,
                    parsed,
                    elapsedMs,
                    elapsedSec,
                    rowsPerSec,
                    null,
                    new CpeSyncMeta(sha256, lastModified, size)
            );
        }

        public static SyncResult executedUpload(
                int vIns,
                int pIns,
                int parsed,
                long elapsedMs,
                double elapsedSec,
                double rowsPerSec,
                String sourceFilename
        ) {
            return new SyncResult(
                    CpeSyncSourceMode.UPLOAD,
                    false,
                    vIns,
                    pIns,
                    parsed,
                    elapsedMs,
                    elapsedSec,
                    rowsPerSec,
                    sourceFilename,
                    new CpeSyncMeta(null, null, null)
            );
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