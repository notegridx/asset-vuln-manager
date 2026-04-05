package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CveSyncState;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaCpe;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaNode;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaNodeType;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaOperator;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeNameParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CveFeedMetaParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.CveSyncStateRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaNodeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import jakarta.persistence.EntityManager;
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
import java.util.function.Function;
import java.util.stream.Collectors;

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
 * - VulnerabilityAffectedCpe:
 *   replaced per vulnerability on each sync so removed CPEs are reflected too
 */
@Service
public class CveFeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(CveFeedSyncService.class);

    private static final String SOURCE_NVD = "NVD";

    // tune
    private static final int LOG_EVERY_VULN = 200;
    private static final int FLUSH_EVERY = 250;     // JPA flush/clear frequency within chunk
    private static final int TX_CHUNK_VULN = 250;   // number of vulnerabilities per chunkTx

    private final NvdCveFeedClient feedClient;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
    private final VulnerabilityCriteriaNodeRepository criteriaNodeRepository;
    private final VulnerabilityCriteriaCpeRepository criteriaCpeRepository;
    private final CveSyncStateRepository syncStateRepository;

    // for canonical linking (vendor/product id & normalization)
    private final CpeNameParser cpeNameParser;
    private final VendorProductNormalizer normalizer;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;
    private final VulnerabilityKeyService vulnerabilityKeyService;

    private final EntityManager em;
    private final TransactionTemplate chunkTx;

    private final CveFeedMetaParser metaParser = new CveFeedMetaParser();

    // IMPORTANT: prevent JsonParser.close() from closing underlying stream (GZIP)
    private final JsonFactory jsonFactory;
    private final ObjectMapper objectMapper;

    // small-ish caches (LRU)
    private final Map<String, Long> vendorIdCache = new LruMap<>(50_000);
    private final Map<String, Long> productIdCache = new LruMap<>(200_000);

    public CveFeedSyncService(
            NvdCveFeedClient feedClient,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityAffectedCpeRepository affectedCpeRepository,
            VulnerabilityCriteriaNodeRepository criteriaNodeRepository,
            VulnerabilityCriteriaCpeRepository criteriaCpeRepository,
            CveSyncStateRepository syncStateRepository,
            CpeNameParser cpeNameParser,
            VendorProductNormalizer normalizer,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository,
            VulnerabilityKeyService vulnerabilityKeyService,
            EntityManager em,
            PlatformTransactionManager txManager
    ) {
        this.feedClient = feedClient;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.affectedCpeRepository = affectedCpeRepository;
        this.criteriaNodeRepository = criteriaNodeRepository;
        this.criteriaCpeRepository = criteriaCpeRepository;
        this.syncStateRepository = syncStateRepository;

        this.cpeNameParser = cpeNameParser;
        this.normalizer = normalizer;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
        this.vulnerabilityKeyService = vulnerabilityKeyService;

        this.em = em;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.chunkTx = tt;

        JsonFactory jf = new JsonFactory();
        jf.disable(JsonParser.Feature.AUTO_CLOSE_SOURCE);
        this.jsonFactory = jf;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Feed-based sync called from AdminCveController (Run CVE feed sync).
     * This method matches the existing controller signature.
     */
    public SyncResult sync(NvdCveFeedClient.FeedKind kind, boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        String feedName = feedName(kind);

        CveFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(kind, metaParser);

        CveSyncState state = syncStateRepository.findByFeedName(feedName)
                .orElseGet(() -> new CveSyncState(feedName));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CVE feed sync skipped (meta unchanged). feedName={}, kind={}, sha256={}, lastModified={}, size={}",
                    feedName, kind, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skipped(meta.sha256(), meta.lastModified(), meta.size());
        }

        Path tmp = null;
        try {
            tmp = feedClient.downloadJsonGzToTempFile(kind);
            long bytes = Files.size(tmp);
            log.info("CVE feed downloaded to temp: kind={}, file={}, bytes={}, force={}, cap={}", kind, tmp, bytes, force, safeMax);

            try (InputStream in = Files.newInputStream(tmp)) {
                ParseUpsertResult r = parseAndUpsertJsonGzChunked(in, safeMax);

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

    private String feedName(NvdCveFeedClient.FeedKind kind) {
        return feedName(kind, null);
    }

    public SyncResult sync(NvdCveFeedClient.FeedKind kind, Integer year, boolean force, int maxItems) throws IOException {
        int safeMax = clamp(maxItems, 1, 5_000_000);
        LocalDateTime now = LocalDateTime.now();

        String feedName = feedName(kind, year);

        CveFeedMetaParser.FeedMeta meta = feedClient.fetchMeta(kind, year, metaParser);

        CveSyncState state = syncStateRepository.findByFeedName(feedName)
                .orElseGet(() -> new CveSyncState(feedName));

        boolean same = state.isSameMeta(meta.sha256(), meta.lastModified(), meta.size());
        if (!force && same) {
            log.info("CVE feed sync skipped (meta unchanged). feedName={}, kind={}, year={}, sha256={}, lastModified={}, size={}",
                    feedName, kind, year, meta.sha256(), meta.lastModified(), meta.size());
            return SyncResult.skipped(meta.sha256(), meta.lastModified(), meta.size());
        }

        Path tmp = null;
        try {
            tmp = feedClient.downloadJsonGzToTempFile(kind, year);
            long bytes = Files.size(tmp);
            log.info("CVE feed downloaded to temp: kind={}, year={}, file={}, bytes={}, force={}, cap={}",
                    kind, year, tmp, bytes, force, safeMax);

            try (InputStream in = Files.newInputStream(tmp)) {
                ParseUpsertResult r = parseAndUpsertJsonGzChunked(in, safeMax);

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

            while (p.nextToken() != null) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (!"vulnerabilities".equals(field) || v != JsonToken.START_ARRAY) {
                    p.skipChildren();
                    continue;
                }

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

                break;
            }
        }

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

    private ParsedVulnerability parseOneVulnerabilityItem(JsonParser p) throws IOException {
        String cveId = null;
        String description = null;

        String cvssVersion = null;
        BigDecimal cvssScore = null;

        LocalDateTime publishedAt = null;
        LocalDateTime lastModifiedAt = null;

        List<ParsedAffectedCpe> affected = new ArrayList<>();
        List<ParsedCriteriaRoot> criteriaRoots = new ArrayList<>();

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
                p.skipChildren();
                continue;
            }

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
                    List<NvdCveResponse.Configurations> configurations =
                            objectMapper.readValue(p, new TypeReference<List<NvdCveResponse.Configurations>>() {});
                    CriteriaParseBundle bundle = buildCriteriaParseBundle(configurations);
                    affected.addAll(bundle.affected());
                    criteriaRoots.addAll(bundle.roots());
                    continue;
                }

                p.skipChildren();
            }
        }

        if (cveId == null) return null;

        ParsedVulnerability out = new ParsedVulnerability();
        out.cveId = cveId;
        out.description = description;
        out.cvssVersion = cvssVersion;
        out.cvssScore = cvssScore;
        out.publishedAt = publishedAt;
        out.lastModifiedAt = lastModifiedAt;
        out.affected = affected;
        out.criteriaRoots = criteriaRoots;

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

            int prio = cvssPriority(f);
            if (best == null || prio < best.priority) {
                pick.priority = prio;
                best = pick;
            }
        }

        return best;
    }

    private int cvssPriority(String metricsField) {
        if ("cvssMetricV31".equals(metricsField)) return 0;
        if ("cvssMetricV30".equals(metricsField)) return 1;
        if ("cvssMetricV2".equals(metricsField)) return 2;
        return 9;
    }

    private CvssPick parseFirstCvssMetricArrayElement(JsonParser p) throws IOException {
        CvssPick out = null;

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
        }

        p.skipChildren();
        while (p.currentToken() != JsonToken.END_ARRAY) {
            if (p.nextToken() == null) break;
            if (p.currentToken() == JsonToken.END_ARRAY) break;
            p.skipChildren();
        }

        return out;
    }

    private CriteriaParseBundle buildCriteriaParseBundle(List<NvdCveResponse.Configurations> configurationsList) {
        List<ParsedAffectedCpe> affected = new ArrayList<>();
        List<ParsedCriteriaRoot> roots = new ArrayList<>();

        if (configurationsList == null || configurationsList.isEmpty()) {
            return new CriteriaParseBundle(affected, roots);
        }

        int rootGroupNo = 0;
        for (NvdCveResponse.Configurations configurations : configurationsList) {
            if (configurations == null || configurations.nodes() == null || configurations.nodes().isEmpty()) {
                rootGroupNo++;
                continue;
            }

            List<ParsedCriteriaNode> topNodes = new ArrayList<>();
            for (NvdCveResponse.Node node : configurations.nodes()) {
                ParsedCriteriaNode parsed = toParsedCriteriaNode(node, affected);
                if (parsed != null) {
                    topNodes.add(parsed);
                }
            }

            if (topNodes.isEmpty()) {
                rootGroupNo++;
                continue;
            }

            CriteriaOperator rootOperator = parseCriteriaOperator(configurations.operator());
            boolean rootNegate = Boolean.TRUE.equals(configurations.negate());

            ParsedCriteriaNode rootNode;
            if (topNodes.size() == 1) {
                ParsedCriteriaNode only = topNodes.get(0);

                if (rootOperator != null || rootNegate) {
                    rootNode = new ParsedCriteriaNode(
                            CriteriaNodeType.OPERATOR,
                            rootOperator == null ? CriteriaOperator.OR : rootOperator,
                            rootNegate,
                            List.of(only),
                            List.of()
                    );
                } else {
                    rootNode = only;
                }
            } else {
                rootNode = new ParsedCriteriaNode(
                        CriteriaNodeType.OPERATOR,
                        rootOperator == null ? CriteriaOperator.OR : rootOperator,
                        rootNegate,
                        topNodes,
                        List.of()
                );
            }

            roots.add(new ParsedCriteriaRoot(rootGroupNo, rootNode));
            rootGroupNo++;
        }

        return new CriteriaParseBundle(affected, roots);
    }

    private ParsedCriteriaNode toParsedCriteriaNode(
            NvdCveResponse.Node node,
            List<ParsedAffectedCpe> flatOut
    ) {
        if (node == null) return null;

        List<ParsedCriteriaNode> children = new ArrayList<>();

        if (node.children() != null) {
            for (NvdCveResponse.Node child : node.children()) {
                ParsedCriteriaNode parsedChild = toParsedCriteriaNode(child, flatOut);
                if (parsedChild != null) {
                    children.add(parsedChild);
                }
            }
        }

        if (node.nodes() != null) {
            for (NvdCveResponse.Node child : node.nodes()) {
                ParsedCriteriaNode parsedChild = toParsedCriteriaNode(child, flatOut);
                if (parsedChild != null) {
                    children.add(parsedChild);
                }
            }
        }

        List<ParsedCriteriaCpe> leafCpes = new ArrayList<>();
        if (node.cpeMatch() != null) {
            for (NvdCveResponse.CpeMatch m : node.cpeMatch()) {
                ParsedCriteriaCpe parsedCpe = toParsedCriteriaCpe(m, flatOut);
                if (parsedCpe != null) {
                    leafCpes.add(parsedCpe);
                }
            }
        }

        boolean negate = Boolean.TRUE.equals(node.negate());
        CriteriaOperator operator = parseCriteriaOperator(node.operator());

        if (children.isEmpty() && leafCpes.isEmpty()) {
            return null;
        }

        if (children.isEmpty()) {
            return new ParsedCriteriaNode(
                    CriteriaNodeType.LEAF_GROUP,
                    null,
                    negate,
                    List.of(),
                    leafCpes
            );
        }

        if (!leafCpes.isEmpty()) {
            children.add(new ParsedCriteriaNode(
                    CriteriaNodeType.LEAF_GROUP,
                    null,
                    false,
                    List.of(),
                    leafCpes
            ));
        }

        return new ParsedCriteriaNode(
                CriteriaNodeType.OPERATOR,
                operator == null ? CriteriaOperator.OR : operator,
                negate,
                children,
                List.of()
        );
    }

    private ParsedCriteriaCpe toParsedCriteriaCpe(
            NvdCveResponse.CpeMatch m,
            List<ParsedAffectedCpe> flatOut
    ) {
        if (m == null) return null;
        if (Boolean.FALSE.equals(m.vulnerable())) return null;

        String criteria = norm(m.criteria());
        if (criteria == null || !criteria.startsWith("cpe:2.3:")) return null;

        String vendorNorm = null;
        String productNorm = null;
        Long vendorId = null;
        Long productId = null;

        String cpePart = null;
        String targetSw = null;
        String targetHw = null;

        Optional<CpeNameParser.ParsedCpe23> parsedOpt = cpeNameParser.parse(criteria);
        if (parsedOpt.isPresent()) {
            CpeNameParser.ParsedCpe23 parsed = parsedOpt.get();

            cpePart = normalizeCpePart(parsed.part());
            targetSw = normalizeTargetSw(parsed.targetSw());
            targetHw = normalizeTargetHw(parsed.targetHw());

            vendorNorm = normalizer.normalizeVendor(parsed.vendor());
            productNorm = normalizer.normalizeProduct(parsed.product());

            if (vendorNorm != null && productNorm != null) {
                vendorId = cachedVendorId(vendorNorm);
                if (vendorId != null) {
                    productId = cachedProductId(vendorId, productNorm);
                }
            }
        }

        String vsi = nullToEmpty(m.versionStartIncluding());
        String vse = nullToEmpty(m.versionStartExcluding());
        String vei = nullToEmpty(m.versionEndIncluding());
        String vee = nullToEmpty(m.versionEndExcluding());

        ParsedAffectedCpe flat = new ParsedAffectedCpe();
        flat.criteria = criteria;
        flat.cpePart = cpePart;
        flat.targetSw = targetSw;
        flat.targetHw = targetHw;
        flat.versionStartIncluding = vsi;
        flat.versionStartExcluding = vse;
        flat.versionEndIncluding = vei;
        flat.versionEndExcluding = vee;
        flatOut.add(flat);

        return new ParsedCriteriaCpe(
                criteria,
                vendorId,
                productId,
                vendorNorm,
                productNorm,
                cpePart,
                targetSw,
                targetHw,
                vsi,
                vse,
                vei,
                vee,
                true
        );
    }

    private ChunkResult upsertChunk(List<ParsedVulnerability> chunk) {
        int vulnUpserted = 0;
        int affectedInserted = 0;

        if (chunk == null || chunk.isEmpty()) {
            return new ChunkResult(0, 0);
        }

        List<String> externalIds = chunk.stream()
                .filter(Objects::nonNull)
                .map(pv -> pv.cveId)
                .filter(Objects::nonNull)
                .filter(s -> !s.isBlank())
                .distinct()
                .toList();

        Map<String, Vulnerability> existingByExternalId = vulnerabilityRepository
                .findBySourceAndExternalIdIn(SOURCE_NVD, externalIds)
                .stream()
                .collect(Collectors.toMap(
                        Vulnerability::getExternalId,
                        Function.identity()
                ));

        int processedInTx = 0;

        for (ParsedVulnerability pv : chunk) {
            if (pv == null || pv.cveId == null || pv.cveId.isBlank()) {
                continue;
            }

            Vulnerability v = existingByExternalId.get(pv.cveId);
            boolean isNew = (v == null);

            LocalDateTime oldLastModifiedAt = null;
            if (!isNew) {
                oldLastModifiedAt = v.getLastModifiedAt();
            }

            if (v == null) {
                v = new Vulnerability(SOURCE_NVD, pv.cveId);
                existingByExternalId.put(pv.cveId, v);
            }

            v.applyNvdDetails(
                    pv.description,
                    pv.cvssVersion,
                    pv.cvssScore,
                    pv.publishedAt,
                    pv.lastModifiedAt
            );

            v = vulnerabilityRepository.save(v);
            vulnUpserted++;

            boolean structureChanged = isNew || !Objects.equals(oldLastModifiedAt, pv.lastModifiedAt);

            if (structureChanged) {
                replaceCriteriaTree(v, pv.criteriaRoots);

                // Replace affected CPEs per vulnerability so removed CPEs are reflected too.
                affectedInserted += replaceAffectedCpes(v, pv.affected);
            }

            processedInTx++;
            if (processedInTx % FLUSH_EVERY == 0) {
                try {
                    em.flush();
                    em.clear();
                } catch (Exception e) {
                    log.warn("flush/clear failed (ignored). err={}", safeMsg(e));
                }
            }
        }

        try {
            em.flush();
            em.clear();
        } catch (Exception e) {
            log.warn("final flush/clear failed (ignored). err={}", safeMsg(e));
        }

        return new ChunkResult(vulnUpserted, affectedInserted);
    }

    private void replaceCriteriaTree(Vulnerability vulnerability, List<ParsedCriteriaRoot> roots) {
        if (vulnerability == null || vulnerability.getId() == null) {
            return;
        }

        Long vulnerabilityId = vulnerability.getId();

        criteriaCpeRepository.deleteByVulnerabilityId(vulnerabilityId);
        criteriaNodeRepository.deleteByVulnerabilityId(vulnerabilityId);

        try {
            em.flush();
            em.clear();
        } catch (Exception e) {
            log.warn("flush/clear after criteria delete failed. vulnerabilityId={}, err={}",
                    vulnerabilityId, safeMsg(e));
            throw e;
        }

        if (roots == null || roots.isEmpty()) {
            return;
        }

        Vulnerability managedV = em.getReference(Vulnerability.class, vulnerabilityId);

        int rootSort = 0;
        for (ParsedCriteriaRoot root : roots) {
            if (root == null || root.rootNode() == null) {
                continue;
            }
            persistCriteriaNodeRecursive(
                    managedV,
                    null,
                    root.rootGroupNo(),
                    rootSort++,
                    root.rootNode()
            );
        }
    }

    private void persistCriteriaNodeRecursive(
            Vulnerability vulnerability,
            Long parentId,
            int rootGroupNo,
            int sortOrder,
            ParsedCriteriaNode parsed
    ) {
        if (parsed == null) return;

        VulnerabilityCriteriaNode savedNode = criteriaNodeRepository.save(
                new VulnerabilityCriteriaNode(
                        vulnerability,
                        parentId,
                        rootGroupNo,
                        parsed.nodeType(),
                        parsed.operator(),
                        parsed.negate(),
                        sortOrder
                )
        );

        int pending = 0;

        if (parsed.nodeType() == CriteriaNodeType.LEAF_GROUP && parsed.cpes() != null) {
            for (ParsedCriteriaCpe cpe : parsed.cpes()) {
                if (cpe == null) continue;

                VulnerabilityCriteriaCpe row = new VulnerabilityCriteriaCpe(
                        savedNode.getId(),
                        vulnerability,
                        cpe.cpeName(),
                        cpe.cpeVendorId(),
                        cpe.cpeProductId(),
                        cpe.vendorNorm(),
                        cpe.productNorm(),
                        cpe.cpePart(),
                        cpe.targetSw(),
                        cpe.targetHw(),
                        cpe.versionStartIncluding(),
                        cpe.versionStartExcluding(),
                        cpe.versionEndIncluding(),
                        cpe.versionEndExcluding(),
                        cpe.matchVulnerable()
                );
                criteriaCpeRepository.save(row);
                pending++;

                if (pending >= FLUSH_EVERY) {
                    em.flush();
                    em.clear();
                    pending = 0;
                    vulnerability = em.getReference(Vulnerability.class, vulnerability.getId());
                }
            }
        }

        if (pending > 0) {
            em.flush();
            em.clear();
            vulnerability = em.getReference(Vulnerability.class, vulnerability.getId());
        }

        if (parsed.children() != null && !parsed.children().isEmpty()) {
            int childSort = 0;
            for (ParsedCriteriaNode child : parsed.children()) {
                persistCriteriaNodeRecursive(
                        vulnerability,
                        savedNode.getId(),
                        rootGroupNo,
                        childSort++,
                        child
                );
            }
        }
    }

    private int replaceAffectedCpes(Vulnerability vulnerability, List<ParsedAffectedCpe> items) {
        if (vulnerability == null || vulnerability.getId() == null) {
            return 0;
        }

        Long vulnerabilityId = vulnerability.getId();

        affectedCpeRepository.deleteByVulnerabilityId(vulnerabilityId);

        try {
            em.flush();
            em.clear();
        } catch (Exception e) {
            log.warn("flush/clear after affected delete failed. vulnerabilityId={}, err={}",
                    vulnerabilityId, safeMsg(e));
            throw e;
        }

        if (items == null || items.isEmpty()) {
            return 0;
        }

        int inserted = 0;
        int pending = 0;

        Vulnerability managedV = em.getReference(Vulnerability.class, vulnerabilityId);
        Set<String> seenNaturalKeys = new HashSet<>();

        for (ParsedAffectedCpe a : items) {
            if (a == null) {
                continue;
            }

            String criteria = norm(a.criteria);
            if (criteria == null || !criteria.startsWith("cpe:2.3:")) {
                continue;
            }

            String vsi = nullToEmpty(a.versionStartIncluding);
            String vse = nullToEmpty(a.versionStartExcluding);
            String vei = nullToEmpty(a.versionEndIncluding);
            String vee = nullToEmpty(a.versionEndExcluding);

            String naturalKey = vulnerabilityId + "|" + criteria + "|" + vsi + "|" + vse + "|" + vei + "|" + vee;
            if (!seenNaturalKeys.add(naturalKey)) {
                continue;
            }

            Long vendorId = null;
            Long productId = null;
            String vendorNorm = null;
            String productNorm = null;
            String cpePart = normalizeCpePart(a.cpePart);
            String targetSw = normalizeTargetSw(a.targetSw);
            String targetHw = normalizeTargetHw(a.targetHw);

            Optional<CpeNameParser.ParsedCpe23> parsedOpt = cpeNameParser.parse(criteria);
            if (parsedOpt.isPresent()) {
                CpeNameParser.ParsedCpe23 parsed = parsedOpt.get();

                if (cpePart == null) {
                    cpePart = normalizeCpePart(parsed.part());
                }
                if (targetSw == null) {
                    targetSw = normalizeTargetSw(parsed.targetSw());
                }
                if (targetHw == null) {
                    targetHw = normalizeTargetHw(parsed.targetHw());
                }

                vendorNorm = normalizer.normalizeVendor(parsed.vendor());
                productNorm = normalizer.normalizeProduct(parsed.product());

                if (vendorNorm != null && productNorm != null) {
                    vendorId = cachedVendorId(vendorNorm);
                    if (vendorId != null) {
                        productId = cachedProductId(vendorId, productNorm);
                    }
                }
            }

            String dedupeKey = vulnerabilityKeyService.buildAffectedCpeKey(
                    vulnerabilityId,
                    criteria,
                    vsi,
                    vse,
                    vei,
                    vee
            );

            VulnerabilityAffectedCpe row = new VulnerabilityAffectedCpe(
                    managedV,
                    criteria,
                    vendorId,
                    productId,
                    vendorNorm,
                    productNorm,
                    cpePart,
                    targetSw,
                    targetHw,
                    vsi,
                    vse,
                    vei,
                    vee,
                    null,
                    0
            );
            row.setDedupeKey(dedupeKey);

            try {
                affectedCpeRepository.save(row);
                inserted++;
                pending++;
            } catch (DataIntegrityViolationException ex) {
                if (isDuplicateConstraint(ex)) {
                    log.debug("Duplicate vulnerability_affected_cpes ignored. vulnerabilityId={}, cpeName={}", vulnerabilityId, criteria);
                    continue;
                }
                throw ex;
            }

            if (pending >= FLUSH_EVERY) {
                try {
                    em.flush();
                    em.clear();
                    managedV = em.getReference(Vulnerability.class, vulnerabilityId);
                } catch (Exception e) {
                    log.warn("flush/clear failed during affected replace. err={}", safeMsg(e));
                    throw e;
                }
                pending = 0;
            }
        }

        if (pending > 0) {
            try {
                em.flush();
                em.clear();
            } catch (Exception e) {
                log.warn("flush/clear failed at affected replace tail. err={}", safeMsg(e));
                throw e;
            }
        }

        return inserted;
    }

    private boolean isDuplicateConstraint(Throwable ex) {
        Throwable t = ex;
        while (t != null) {
            String msg = t.getMessage();
            if (msg != null) {
                String m = msg.toLowerCase(Locale.ROOT);
                if (m.contains("duplicate")
                        || m.contains("unique")
                        || m.contains("constraint")
                        || m.contains("uq_vac_dedupe_key")
                        || m.contains("uq_vac_dedupe")) {
                    return true;
                }
            }
            t = t.getCause();
        }
        return false;
    }

    private Long cachedVendorId(String vendorNorm) {
        if (vendorNorm == null) return null;

        Long cached = vendorIdCache.get(vendorNorm);
        if (cached != null) return cached;

        Long id = cpeVendorRepository.findByNameNorm(vendorNorm)
                .map(CpeVendor::getId)
                .orElse(null);

        if (id == null) {
            try {
                CpeVendor created = new CpeVendor(vendorNorm, null);
                created.markAsNvdCve();
                created = cpeVendorRepository.save(created);

                id = created.getId();
                log.debug("CPE vendor created from CVE feed sync: nameNorm={}, source={}", vendorNorm, created.getSource());
            } catch (DataIntegrityViolationException dup) {
                id = cpeVendorRepository.findByNameNorm(vendorNorm)
                        .map(CpeVendor::getId)
                        .orElse(null);
            }
        }

        if (id != null) vendorIdCache.put(vendorNorm, id);
        return id;
    }

    private Long cachedProductId(Long vendorId, String productNorm) {
        if (vendorId == null || productNorm == null) return null;

        String key = vendorId + "|" + productNorm;
        Long cached = productIdCache.get(key);
        if (cached != null) return cached;

        Long id = cpeProductRepository.findByVendorIdAndNameNorm(vendorId, productNorm)
                .map(CpeProduct::getId)
                .orElse(null);

        if (id == null) {
            try {
                CpeVendor vendorRef = cpeVendorRepository.getReferenceById(vendorId);

                CpeProduct created = new CpeProduct(vendorRef, productNorm, null);
                created.markAsNvdCve();
                created = cpeProductRepository.save(created);

                id = created.getId();
                log.debug("CPE product created from CVE feed sync: vendorId={}, nameNorm={}, source={}",
                        vendorId, productNorm, created.getSource());
            } catch (DataIntegrityViolationException dup) {
                id = cpeProductRepository.findByVendorIdAndNameNorm(vendorId, productNorm)
                        .map(CpeProduct::getId)
                        .orElse(null);
            }
        }

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

        try {
            return OffsetDateTime.parse(s).toLocalDateTime();
        } catch (DateTimeParseException ignore) {
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

    private static CriteriaOperator parseCriteriaOperator(String raw) {
        String s = norm(raw);
        if (s == null) return null;
        try {
            return CriteriaOperator.valueOf(s.toUpperCase(Locale.ROOT));
        } catch (Exception ex) {
            return null;
        }
    }

    private static String normalizeCpePart(String raw) {
        String s = norm(raw);
        if (s == null) {
            return null;
        }

        String x = s.toLowerCase(Locale.ROOT);
        return switch (x) {
            case "a", "o", "h" -> x;
            default -> x;
        };
    }

    private static String normalizeTargetSw(String raw) {
        String s = norm(raw);
        if (s == null) {
            return null;
        }

        String x = s.toLowerCase(Locale.ROOT);
        return switch (x) {
            case "windows", "microsoft_windows" -> "windows";
            case "mac_os", "macos", "mac_os_x", "darwin" -> "mac_os";
            case "linux", "gnu_linux" -> "linux";
            case "iphone_os", "ios", "ipad_os", "android" -> x;
            case "*", "-" -> x;
            default -> x;
        };
    }

    private static String normalizeTargetHw(String raw) {
        String s = norm(raw);
        if (s == null) {
            return null;
        }
        return s.toLowerCase(Locale.ROOT);
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

    private static String nullToEmpty(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.isEmpty() ? "" : t;
    }

    private static final class ParsedVulnerability {
        String cveId;
        String description;
        String cvssVersion;
        BigDecimal cvssScore;
        LocalDateTime publishedAt;
        LocalDateTime lastModifiedAt;
        List<ParsedAffectedCpe> affected = new ArrayList<>();
        List<ParsedCriteriaRoot> criteriaRoots = new ArrayList<>();
    }

    private static final class ParsedAffectedCpe {
        String criteria;
        String cpePart;
        String targetSw;
        String targetHw;
        String versionStartIncluding;
        String versionStartExcluding;
        String versionEndIncluding;
        String versionEndExcluding;
    }

    private record ParsedCriteriaRoot(
            int rootGroupNo,
            ParsedCriteriaNode rootNode
    ) {
    }

    private record ParsedCriteriaNode(
            CriteriaNodeType nodeType,
            CriteriaOperator operator,
            boolean negate,
            List<ParsedCriteriaNode> children,
            List<ParsedCriteriaCpe> cpes
    ) {
    }

    private record ParsedCriteriaCpe(
            String cpeName,
            Long cpeVendorId,
            Long cpeProductId,
            String vendorNorm,
            String productNorm,
            String cpePart,
            String targetSw,
            String targetHw,
            String versionStartIncluding,
            String versionStartExcluding,
            String versionEndIncluding,
            String versionEndExcluding,
            boolean matchVulnerable
    ) {
    }

    private record CriteriaParseBundle(
            List<ParsedAffectedCpe> affected,
            List<ParsedCriteriaRoot> roots
    ) {
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