package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import dev.notegridx.security.assetvulnmanager.domain.CveSyncState;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeNameParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CveFeedMetaParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.CveSyncStateRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.*;

/**
 * CVE Feed Sync (JSON feed .json.gz) - streaming safe, chunked upsert.
 * <p>
 * - Meta check (sha256/lastModified/size) -> skip unless force
 * - Download json.gz to temp file
 * - GZIPInputStream + Jackson streaming parse
 * - Chunked TX upsert (REQUIRES_NEW) similar to CpeFeedSyncService
 * <p>
 * Upsert policy aligned with current domain:
 * - Vulnerability unique: (source, external_id) -> update via applyNvdDetails()
 * - VulnerabilityAffectedCpe unique:
 *   (vulnerability_id, cpe_name, version_start_including, version_start_excluding, version_end_including, version_end_excluding)
 *   -> insert-only, duplicates ignored
 */
@Service
public class CveFeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(CveFeedSyncService.class);

    private static final String SOURCE_NVD = "NVD";

    // tune
    private static final int LOG_EVERY_VULN = 200;
    private static final int FLUSH_EVERY = 200;     // JPA flush/clear frequency within chunk
    private static final int TX_CHUNK_VULN = 200;   // number of vulnerabilities per chunkTx

    private final NvdCveFeedClient feedClient;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
    private final CveSyncStateRepository syncStateRepository;

    // for canonical linking (vendor/product id & normalization)
    private final CpeNameParser cpeNameParser;
    private final VendorProductNormalizer normalizer;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    private final EntityManager em;
    private final TransactionTemplate chunkTx;

    private final CveFeedMetaParser metaParser = new CveFeedMetaParser();

    // IMPORTANT: prevent JsonParser.close() from closing underlying stream (GZIP)
    private final JsonFactory jsonFactory;

    // small-ish caches (LRU)
    private final Map<String, Long> vendorIdCache = new LruMap<>(50_000);
    private final Map<String, Long> productIdCache = new LruMap<>(200_000);

    public CveFeedSyncService(
            NvdCveFeedClient feedClient,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            CveSyncStateRepository syncStateRepository,
            CpeNameParser cpeNameParser,
            VendorProductNormalizer normalizer,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            EntityManager em,
            PlatformTransactionManager txManager
    ) {
        this.feedClient = feedClient;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.affectedCpeRepository = affectedCpeRepository;
        this.syncStateRepository = syncStateRepository;

        this.cpeNameParser = cpeNameParser;
        this.normalizer = normalizer;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;

        this.em = em;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.chunkTx = tt;

        JsonFactory jf = new JsonFactory();
        jf.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
        this.jsonFactory = jf;
    }

    /**
     * Feed-based sync called from AdminCveController (Run CVE feed sync).
     * This method matches the existing controller signature.
     */
    public SyncResult sync(NvdCveFeedClient.FeedKind kind, boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        String feedName = feedName(kind);

        // 1) META fetch (small)
        CveFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(kind, metaParser);

        // 2) compare with sync_state
        CveSyncState state = syncStateRepository.findByFeedName(feedName)
                .orElseGet(() -> new CveSyncState(feedName));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CVE feed sync skipped (meta unchanged). feedName={}, kind={}, sha256={}, lastModified={}, size={}",
                    feedName, kind, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skipped(meta.sha256(), meta.lastModified(), meta.size());
        }

        // 3) download json.gz -> temp file
        Path tmp = null;
        try {
            tmp = feedClient.downloadJsonGzToTempFile(kind);
            long bytes = Files.size(tmp);
            log.info("CVE feed downloaded to temp: kind={}, file={}, bytes={}, force={}, cap={}", kind, tmp, bytes, force, safeMax);

            // 4) parse & upsert with chunked transactions
            try (InputStream in = Files.newInputStream(tmp)) {
                ParseUpsertResult r = parseAndUpsertJsonGzChunked(in, safeMax);

                // 5) update sync state
                state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
                syncStateRepository.save(state);

                log.info("CVE feed sync done: kind={}, feedName={}, vulnerabilitiesUpserted={}, affectedInserted={}, vulnerabilitiesParsed={}, caches(vendor={}, product={})",
                        kind, feedName, r.vulnerabilitiesUpserted, r.affectedCpesInserted, r.vulnerabilitiesParsed,
                        vendorIdCache.size(), productIdCache.size()
                );

                return SyncResult.executed(
                        r.vulnerabilitiesUpserted,
                        r.affectedCpesInserted,
                        r.vulnerabilitiesParsed,
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

    // 旧呼び出し互換（既存の feedName(kind) 呼び出しが全部生きる）
    private String feedName(NvdCveFeedClient.FeedKind kind) {
        return feedName(kind, null);
    }

    public SyncResult sync(NvdCveFeedClient.FeedKind kind, Integer year, boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        String feedName = feedName(kind, year);

        // 1) META fetch (small)
        CveFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(kind, year, metaParser);

        // 2) compare with sync_state
        CveSyncState state = syncStateRepository.findByFeedName(feedName)
                .orElseGet(() -> new CveSyncState(feedName));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CVE feed sync skipped (meta unchanged). feedName={}, kind={}, year={}, sha256={}, lastModified={}, size={}",
                    feedName, kind, year, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skipped(meta.sha256(), meta.lastModified(), meta.size());
        }

        // 3) download json.gz -> temp file
        Path tmp = null;
        try {
            tmp = feedClient.downloadJsonGzToTempFile(kind, year);
            long bytes = Files.size(tmp);
            log.info("CVE feed downloaded to temp: kind={}, year={}, file={}, bytes={}, force={}, cap={}",
                    kind, year, tmp, bytes, force, safeMax);

            // 4) parse & upsert with chunked transactions
            try (InputStream in = Files.newInputStream(tmp)) {
                ParseUpsertResult r = parseAndUpsertJsonGzChunked(in, safeMax);

                // 5) update sync state
                state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
                syncStateRepository.save(state);

                log.info("CVE feed sync done: kind={}, year={}, feedName={}, vulnerabilitiesUpserted={}, affectedInserted={}, vulnerabilitiesParsed={}, caches(vendor={}, product={})",
                        kind, year, feedName,
                        r.vulnerabilitiesUpserted, r.affectedCpesInserted, r.vulnerabilitiesParsed,
                        vendorIdCache.size(), productIdCache.size()
                );

                return SyncResult.executed(
                        r.vulnerabilitiesUpserted,
                        r.affectedCpesInserted,
                        r.vulnerabilitiesParsed,
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

    private ParseUpsertResult parseAndUpsertJsonGzChunked(InputStream jsonGzStream, int maxItems) throws IOException {
        final int[] parsed = {0};
        final int[] vulnUpserted = {0};
        final int[] affectedInserted = {0};

        List<ParsedVulnerability> buffer = new ArrayList<>(TX_CHUNK_VULN);

        try (java.util.zip.GZIPInputStream gin = new java.util.zip.GZIPInputStream(jsonGzStream);
             JsonParser p = jsonFactory.createParser(gin)) {

            // Find "vulnerabilities": [ ... ]
            while (p.nextToken() != null) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (!"vulnerabilities".equals(field) || v != JsonToken.START_ARRAY) {
                    // skip irrelevant field value
                    p.skipChildren();
                    continue;
                }

                // vulnerabilities array
                while (p.nextToken() != JsonToken.END_ARRAY) {
                    if (p.currentToken() != JsonToken.START_OBJECT) {
                        p.skipChildren();
                        continue;
                    }

                    ParsedVulnerability pv = parseOneVulnerabilityItem(p);
                    if (pv == null || pv.cveId == null) continue;

                    parsed[0]++;
                    if (parsed[0] > maxItems) break;

                    buffer.add(pv);

                    if (buffer.size() >= TX_CHUNK_VULN) {
                        List<ParsedVulnerability> chunk = new ArrayList<>(buffer);
                        buffer.clear();

                        chunkTx.execute(status -> {
                            ChunkResult r = upsertChunk(chunk);
                            vulnUpserted[0] += r.vulnUpserted;
                            affectedInserted[0] += r.affectedInserted;
                            return null;
                        });

                        if (parsed[0] % LOG_EVERY_VULN == 0) {
                            log.info("CVE feed sync progress: vulnerabilitiesParsed={}, vulnerabilitiesUpsertedSoFar={}, affectedInsertedSoFar={}",
                                    parsed[0], vulnUpserted[0], affectedInserted[0]);
                        }
                    }
                }

                // array finished (or cap reached)
                break;
            }
        }

        // tail flush
        if (!buffer.isEmpty() && parsed[0] > 0) {
            List<ParsedVulnerability> chunk = new ArrayList<>(buffer);
            buffer.clear();

            chunkTx.execute(status -> {
                ChunkResult r = upsertChunk(chunk);
                vulnUpserted[0] += r.vulnUpserted;
                affectedInserted[0] += r.affectedInserted;
                return null;
            });
        }

        return new ParseUpsertResult(vulnUpserted[0], affectedInserted[0], parsed[0]);
    }

    /**
     * Parse one element of the "vulnerabilities" array.
     * Expected shape (typical NVD 2.0 feed):
     * {
     * "cve": { "id": "...", "descriptions":[...], "metrics":{...}, "configurations":[...] , ... },
     * "published":"2024-..Z",
     * "lastModified":"2024-..Z"
     * }
     * <p>
     * This parser is best-effort and tolerant.
     * It consumes the END_OBJECT token of the item.
     */
    private ParsedVulnerability parseOneVulnerabilityItem(JsonParser p) throws IOException {
        String cveId = null;
        String description = null;

        String cvssVersion = null;
        BigDecimal cvssScore = null;

        LocalDateTime publishedAt = null;
        LocalDateTime lastModifiedAt = null;

        List<ParsedAffectedCpe> affected = new ArrayList<>();

        // item object
        while (p.nextToken() != JsonToken.END_OBJECT) {
            if (p.currentToken() != JsonToken.FIELD_NAME) continue;

            String field = p.currentName();
            JsonToken v = p.nextToken();

            if ("published".equals(field) && v == JsonToken.VALUE_STRING) {
                publishedAt = parseToLocalDateTime(p.getValueAsString());
                continue;
            }
            if ("lastModified".equals(field) && v == JsonToken.VALUE_STRING) {
                lastModifiedAt = parseToLocalDateTime(p.getValueAsString());
                continue;
            }

            if (!"cve".equals(field) || v != JsonToken.START_OBJECT) {
                // skip unknown field value
                p.skipChildren();
                continue;
            }

            // cve object
            while (p.nextToken() != JsonToken.END_OBJECT) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String cf = p.currentName();
                JsonToken cv = p.nextToken();

                if ("id".equals(cf) && cv == JsonToken.VALUE_STRING) {
                    cveId = norm(p.getValueAsString());
                    continue;
                }
                if ("published".equals(cf) && cv == JsonToken.VALUE_STRING) {
                    publishedAt = parseToLocalDateTime(p.getValueAsString());
                    continue;
                }
                if ("lastModified".equals(cf) && cv == JsonToken.VALUE_STRING) {
                    lastModifiedAt = parseToLocalDateTime(p.getValueAsString());
                    continue;
                }
                if ("descriptions".equals(cf) && cv == JsonToken.START_ARRAY) {
                    // prefer English description
                    String desc = parseDescriptionsPreferEn(p);
                    if (desc != null) description = desc;
                    continue;
                }

                if ("metrics".equals(cf) && cv == JsonToken.START_OBJECT) {
                    CvssPick pick = parseMetricsPickBest(p);
                    if (pick != null) {
                        cvssVersion = pick.version;
                        cvssScore = pick.score;
                    }
                    continue;
                }

                if ("configurations".equals(cf) && cv == JsonToken.START_ARRAY) {
                    parseConfigurationsToAffected(p, affected);
                    continue;
                }

                // ignore others
                p.skipChildren();
            }
        }

        if (cveId == null) return null;

        ParsedVulnerability out = new ParsedVulnerability();
        out.cveId = cveId;
        out.title = null; // NVD feed doesn't reliably provide a "title" -> keep null
        out.description = description;
        out.cvssVersion = cvssVersion;
        out.cvssScore = cvssScore;
        out.publishedAt = publishedAt;
        out.lastModifiedAt = lastModifiedAt;
        out.affected = affected;

        return out;
    }

    private String parseDescriptionsPreferEn(JsonParser p) throws IOException {
        String any = null;
        String en = null;

        while (p.nextToken() != JsonToken.END_ARRAY) {
            if (p.currentToken() != JsonToken.START_OBJECT) {
                p.skipChildren();
                continue;
            }

            String lang = null;
            String value = null;

            while (p.nextToken() != JsonToken.END_OBJECT) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String f = p.currentName();
                JsonToken v = p.nextToken();

                if ("lang".equals(f) && v == JsonToken.VALUE_STRING) {
                    lang = norm(p.getValueAsString());
                } else if ("value".equals(f) && v == JsonToken.VALUE_STRING) {
                    value = norm(p.getValueAsString());
                } else {
                    p.skipChildren();
                }
            }

            if (value != null) {
                if (any == null) any = value;
                if ("en".equalsIgnoreCase(lang)) {
                    en = value;
                }
            }
        }

        return (en != null) ? en : any;
    }

    /**
     * metrics:
     * {
     * "cvssMetricV31":[{ "cvssData":{"version":"3.1","baseScore":7.5}, ... }],
     * "cvssMetricV30":[...],
     * "cvssMetricV2":[{ "cvssData":{"version":"2.0","baseScore":5.0}, ... }]
     * }
     * <p>
     * Pick the best available in order: V31 -> V30 -> V2
     */
    private CvssPick parseMetricsPickBest(JsonParser p) throws IOException {
        CvssPick best = null;

        while (p.nextToken() != JsonToken.END_OBJECT) {
            if (p.currentToken() != JsonToken.FIELD_NAME) continue;

            String f = p.currentName();
            JsonToken v = p.nextToken();

            boolean isCandidate =
                    "cvssMetricV31".equals(f) ||
                            "cvssMetricV30".equals(f) ||
                            "cvssMetricV2".equals(f);

            if (!isCandidate || v != JsonToken.START_ARRAY) {
                p.skipChildren();
                continue;
            }

            CvssPick pick = parseFirstCvssMetricArrayElement(p);
            if (pick == null) continue;

            // pick priority
            int prio = cvssPriority(f);
            if (best == null || prio < best.priority) {
                pick.priority = prio;
                best = pick;
            }
        }

        return best;
    }

    private int cvssPriority(String metricsField) {
        // lower is better
        if ("cvssMetricV31".equals(metricsField)) return 0;
        if ("cvssMetricV30".equals(metricsField)) return 1;
        if ("cvssMetricV2".equals(metricsField)) return 2;
        return 9;
    }

    private CvssPick parseFirstCvssMetricArrayElement(JsonParser p) throws IOException {
        CvssPick out = null;

        // take only the first element (usually primary)
        if (p.nextToken() == JsonToken.START_OBJECT) {

            String version = null;
            BigDecimal score = null;

            while (p.nextToken() != JsonToken.END_OBJECT) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String f = p.currentName();
                JsonToken v = p.nextToken();

                if ("cvssData".equals(f) && v == JsonToken.START_OBJECT) {
                    while (p.nextToken() != JsonToken.END_OBJECT) {
                        if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                        String df = p.currentName();
                        JsonToken dv = p.nextToken();

                        if ("version".equals(df) && dv == JsonToken.VALUE_STRING) {
                            version = norm(p.getValueAsString());
                        } else if ("baseScore".equals(df) && (dv == JsonToken.VALUE_NUMBER_FLOAT || dv == JsonToken.VALUE_NUMBER_INT)) {
                            score = safeBigDecimal(p.getValueAsString());
                        } else {
                            p.skipChildren();
                        }
                    }
                } else {
                    p.skipChildren();
                }
            }

            if (score != null) {
                out = new CvssPick();
                out.version = version;
                out.score = score;
            }
        } else {
            // array empty
        }

        // skip remaining elements in the array
        p.skipChildren();
        while (p.currentToken() != JsonToken.END_ARRAY) {
            if (p.nextToken() == null) break;
            if (p.currentToken() == JsonToken.END_ARRAY) break;
            p.skipChildren();
        }

        return out;
    }

    private void parseConfigurationsToAffected(JsonParser p, List<ParsedAffectedCpe> out) throws IOException {
        // configurations: [ { "nodes":[ ... ] }, ... ]
        while (p.nextToken() != JsonToken.END_ARRAY) {
            if (p.currentToken() != JsonToken.START_OBJECT) {
                p.skipChildren();
                continue;
            }

            while (p.nextToken() != JsonToken.END_OBJECT) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String f = p.currentName();
                JsonToken v = p.nextToken();

                if ("nodes".equals(f) && v == JsonToken.START_ARRAY) {
                    // nodes: [ node, node, ... ]
                    while (p.nextToken() != JsonToken.END_ARRAY) {
                        if (p.currentToken() != JsonToken.START_OBJECT) {
                            p.skipChildren();
                            continue;
                        }
                        parseNodeRecursive(p, out);
                    }
                } else {
                    p.skipChildren();
                }
            }
        }
    }

    /**
     * Parse node recursively:
     * node: { "cpeMatch":[{...}], "children":[ node, ...], ... }
     */
    private void parseNodeRecursive(JsonParser p, List<ParsedAffectedCpe> out) throws IOException {
        // node object
        while (p.nextToken() != JsonToken.END_OBJECT) {
            if (p.currentToken() != JsonToken.FIELD_NAME) continue;

            String f = p.currentName();
            JsonToken v = p.nextToken();

            if ("cpeMatch".equals(f) && v == JsonToken.START_ARRAY) {
                parseCpeMatchArray(p, out);
                continue;
            }

            if ("children".equals(f) && v == JsonToken.START_ARRAY) {
                while (p.nextToken() != JsonToken.END_ARRAY) {
                    if (p.currentToken() != JsonToken.START_OBJECT) {
                        p.skipChildren();
                        continue;
                    }
                    parseNodeRecursive(p, out);
                }
                continue;
            }

            p.skipChildren();
        }
    }

    private void parseCpeMatchArray(JsonParser p, List<ParsedAffectedCpe> out) throws IOException {
        while (p.nextToken() != JsonToken.END_ARRAY) {
            if (p.currentToken() != JsonToken.START_OBJECT) {
                p.skipChildren();
                continue;
            }

            Boolean vulnerable = null;
            String criteria = null;

            String vsi = null, vse = null, vei = null, vee = null;

            while (p.nextToken() != JsonToken.END_OBJECT) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String f = p.currentName();
                JsonToken v = p.nextToken();

                if ("vulnerable".equals(f) && v == JsonToken.VALUE_TRUE) {
                    vulnerable = true;
                } else if ("vulnerable".equals(f) && v == JsonToken.VALUE_FALSE) {
                    vulnerable = false;
                } else if ("criteria".equals(f) && v == JsonToken.VALUE_STRING) {
                    criteria = norm(p.getValueAsString());
                } else if ("versionStartIncluding".equals(f) && v == JsonToken.VALUE_STRING) {
                    vsi = norm(p.getValueAsString());
                } else if ("versionStartExcluding".equals(f) && v == JsonToken.VALUE_STRING) {
                    vse = norm(p.getValueAsString());
                } else if ("versionEndIncluding".equals(f) && v == JsonToken.VALUE_STRING) {
                    vei = norm(p.getValueAsString());
                } else if ("versionEndExcluding".equals(f) && v == JsonToken.VALUE_STRING) {
                    vee = norm(p.getValueAsString());
                } else {
                    p.skipChildren();
                }
            }

            if (Boolean.FALSE.equals(vulnerable)) continue;
            if (criteria == null || !criteria.startsWith("cpe:2.3:")) continue;

            ParsedAffectedCpe a = new ParsedAffectedCpe();
            a.criteria = criteria;
            a.versionStartIncluding = vsi;
            a.versionStartExcluding = vse;
            a.versionEndIncluding = vei;
            a.versionEndExcluding = vee;
            out.add(a);
        }
    }

    private ChunkResult upsertChunk(List<ParsedVulnerability> chunk) {
        int vulnUpserted = 0;
        int affectedInserted = 0;

        int processedInTx = 0;

        for (ParsedVulnerability pv : chunk) {
            if (pv == null || pv.cveId == null) continue;

            Vulnerability v = vulnerabilityRepository
                    .findBySourceAndExternalId(SOURCE_NVD, pv.cveId)
                    .orElseGet(() -> new Vulnerability(SOURCE_NVD, pv.cveId));

            v.applyNvdDetails(
                    pv.title,
                    pv.description,
                    pv.cvssVersion,
                    pv.cvssScore,
                    pv.publishedAt,
                    pv.lastModifiedAt
            );

            vulnerabilityRepository.save(v);
            vulnUpserted++;

            if (pv.affected != null && !pv.affected.isEmpty()) {
                for (ParsedAffectedCpe a : pv.affected) {
                    affectedInserted += upsertAffectedOne(v, a);
                }
            }

            processedInTx++;
            if (processedInTx % FLUSH_EVERY == 0) {
                // keep persistence context small
                try {
                    em.flush();
                    em.clear();
                } catch (Exception e) {
                    log.warn("flush/clear failed (ignored). err={}", safeMsg(e));
                }
            }
        }

        return new ChunkResult(vulnUpserted, affectedInserted);
    }

    private int upsertAffectedOne(Vulnerability v, ParsedAffectedCpe a) {
        if (a == null) return 0;
        String criteria = norm(a.criteria);
        if (criteria == null || !criteria.startsWith("cpe:2.3:")) return 0;

        Long vendorId = null;
        Long productId = null;
        String vendorNorm = null;
        String productNorm = null;

        // parse vendor/product from criteria -> normalize -> dictionary ids (best effort)
        Optional<CpeNameParser.VendorProduct> vpOpt = cpeNameParser.parseVendorProduct(criteria);
        if (vpOpt.isPresent()) {
            CpeNameParser.VendorProduct vp = vpOpt.get();
            vendorNorm = normalizer.normalizeVendor(vp.vendor());
            productNorm = normalizer.normalizeProduct(vp.product());

            if (vendorNorm != null && productNorm != null) {
                vendorId = cachedVendorId(vendorNorm);
                if (vendorId != null) {
                    productId = cachedProductId(vendorId, productNorm);
                }
            }
        }

        // ---- Phase: insert-only but idempotent (avoid UX_VAC_DEDUPE violations) ----
        // UX_VAC_DEDUPE is based on *_NN columns; align existence check with those keys.
        final long vid = (v == null || v.getId() == null) ? 0L : v.getId();
        final String cpeNameNn = nn(criteria);
        final Long vendorIdNn = nn(vendorId);
        final Long productIdNn = nn(productId);
        final String vendorNormNn = nn(vendorNorm);
        final String productNormNn = nn(productNorm);
        final String vsiNn = nn(a.versionStartIncluding);
        final String vseNn = nn(a.versionStartExcluding);
        final String veiNn = nn(a.versionEndIncluding);
        final String veeNn = nn(a.versionEndExcluding);

        // If already exists, skip without touching persistence context
        if (vid != 0L) {
            boolean exists = affectedCpeRepository
                    .existsByVulnerabilityIdAndCpeNameNnAndCpeVendorIdNnAndCpeProductIdNnAndVendorNormNnAndProductNormNnAndVersionStartIncludingNnAndVersionStartExcludingNnAndVersionEndIncludingNnAndVersionEndExcludingNn(
                            vid,
                            cpeNameNn,
                            vendorIdNn,
                            productIdNn,
                            vendorNormNn,
                            productNormNn,
                            vsiNn,
                            vseNn,
                            veiNn,
                            veeNn
                    );
            if (exists) return 0;
        }

        VulnerabilityAffectedCpe vac = new VulnerabilityAffectedCpe(
                v,
                criteria,
                vendorId,
                productId,
                vendorNorm,
                productNorm,
                a.versionStartIncluding,
                a.versionStartExcluding,
                a.versionEndIncluding,
                a.versionEndExcluding
        );

        try {
            affectedCpeRepository.save(vac);
            // Ensure constraint violations occur here (not later on unrelated SELECT autoFlush)
            em.flush();
            return 1;
        } catch (DataIntegrityViolationException e) {
            // unique constraint hit: ignore
            // But the persistence context may now contain a "broken" entity state -> clear it to avoid
            // "Entry ... has a null identifier" cascading on next autoFlush.
            try {
                em.clear();
            } catch (Exception ignore) {
            }
            return 0;
        } catch (PersistenceException e) {
            // Defensive: some providers throw PersistenceException directly for constraint violations.
            try {
                em.clear();
            } catch (Exception ignore) {
            }
            // Re-throw unexpected persistence issues so chunkTx can rollback properly
            throw e;
        }
    }

    /**
     * Normalize NOT-NULL "NN" columns (schema uses *_NN with defaults).
     * Keep it consistent with your schema defaults:
     * - Strings: null -> ""
     * - Long ids: null -> 0
     */
    private static String nn(String s) {
        return (s == null) ? "" : s;
    }

    private static Long nn(Long v) {
        return (v == null) ? -1L : v;
    }

    private Long cachedVendorId(String vendorNorm) {
        if (vendorNorm == null) return null;

        Long cached = vendorIdCache.get(vendorNorm);
        if (cached != null) return cached;

        Long id = cpeVendorRepository.findByNameNorm(vendorNorm).map(x -> x.getId()).orElse(null);
        if (id != null) vendorIdCache.put(vendorNorm, id);
        return id;
    }

    private Long cachedProductId(Long vendorId, String productNorm) {
        if (vendorId == null || productNorm == null) return null;

        String key = vendorId + "|" + productNorm;
        Long cached = productIdCache.get(key);
        if (cached != null) return cached;

        Long id = cpeProductRepository.findByVendorIdAndNameNorm(vendorId, productNorm).map(x -> x.getId()).orElse(null);
        if (id != null) productIdCache.put(key, id);
        return id;
    }

    private String feedName(NvdCveFeedClient.FeedKind kind, Integer year) {
        return switch (kind) {
            case RECENT -> "cve-feed-recent";
            case MODIFIED -> "cve-feed-modified";
            case YEAR -> "cve-feed-" + (year == null ? "year" : year);
        };
    }

    private static LocalDateTime parseToLocalDateTime(String iso) {
        String s = norm(iso);
        if (s == null) return null;

        // NVD feed uses ISO-8601 with Z
        try {
            return OffsetDateTime.parse(s).toLocalDateTime();
        } catch (DateTimeParseException ignore) {
            // fallback: try LocalDateTime
            try {
                return LocalDateTime.parse(s);
            } catch (DateTimeParseException ignore2) {
                return null;
            }
        }
    }

    private static BigDecimal safeBigDecimal(String s) {
        String t = norm(s);
        if (t == null) return null;
        try {
            return new BigDecimal(t);
        } catch (Exception e) {
            return null;
        }
    }

    private static String norm(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    private static String safeMsg(Throwable e) {
        if (e == null) return null;
        String m = e.getMessage();
        if (m == null) return e.getClass().getSimpleName();
        m = m.replace('\n', ' ').replace('\r', ' ');
        if (m.length() > 400) m = m.substring(0, 400) + "...";
        return e.getClass().getSimpleName() + ": " + m;
    }

    // ---- results ----

    private static final class ParsedVulnerability {
        String cveId;

        String title;
        String description;

        String cvssVersion;
        BigDecimal cvssScore;

        LocalDateTime publishedAt;
        LocalDateTime lastModifiedAt;

        List<ParsedAffectedCpe> affected = new ArrayList<>();
    }

    private static final class ParsedAffectedCpe {
        String criteria;
        String versionStartIncluding;
        String versionStartExcluding;
        String versionEndIncluding;
        String versionEndExcluding;
    }

    private static final class CvssPick {
        String version;
        BigDecimal score;
        int priority = 9;
    }

    private record ChunkResult(int vulnUpserted, int affectedInserted) {
    }

    private record ParseUpsertResult(int vulnerabilitiesUpserted, int affectedCpesInserted, int vulnerabilitiesParsed) {
    }

    public record SyncResult(
            boolean skipped,
            int vulnerabilitiesUpserted,
            int affectedCpesInserted,
            int vulnerabilitiesParsed,
            String metaSha256,
            String metaLastModified,
            Long metaSize
    ) {
        public static SyncResult skipped(String sha256, String lastModified, Long size) {
            return new SyncResult(true, 0, 0, 0, sha256, lastModified, size);
        }

        public static SyncResult executed(int vUp, int aIns, int parsed, String sha256, String lastModified, Long size) {
            return new SyncResult(false, vUp, aIns, parsed, sha256, lastModified, size);
        }
    }

    /**
     * Simple LRU map (access-order).
     */
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
