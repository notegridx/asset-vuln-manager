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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.zip.GZIPInputStream;


@Service
public class CpeFeedSyncService {

    private static final Logger log = LoggerFactory.getLogger(CpeFeedSyncService.class);

    private static final String FEED_NAME = "nvd-cpe-dict";

    private final NvdCpeFeedClient feedClient;

    private final CpeVendorRepository vendorRepository;
    private final CpeProductRepository productRepository;
    private final CpeSyncStateRepository syncStateRepository;

    private final CpeFeedMetaParser metaParser = new CpeFeedMetaParser();
    private final CpeNameParser cpeNameParser = new CpeNameParser();
    private final JsonFactory jsonFactory = new JsonFactory();

    public CpeFeedSyncService(
            NvdCpeFeedClient feedClient,
            CpeVendorRepository vendorRepository,
            CpeProductRepository productRepository,
            CpeSyncStateRepository syncStateRepository
    ) {
        this.feedClient = feedClient;
        this.vendorRepository = vendorRepository;
        this.productRepository = productRepository;
        this.syncStateRepository = syncStateRepository;
    }

    @Transactional
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
        log.info("CPE feed downloaded: bytes={}", gz.length);

        // 4) parse & upsert
        ParseUpsertResult r = parseAndUpsert(gz, safeMax);

        // 5) update sync state
        state.updateMeta(meta.sha256(), meta.lastModified(), meta.size(), now);
        syncStateRepository.save(state);

        log.info("CPE feed sync done: vendorsUpserted={}, productsUpserted={}, cpeParsed={}, cappedAt={}",
                r.vendorsUpserted, r.productsUpserted, r.cpeParsed, safeMax);

        return SyncResult.executed(r.vendorsUpserted, r.productsUpserted, r.cpeParsed,
                meta.sha256(), meta.lastModified(), meta.size());
    }

    private ParseUpsertResult parseAndUpsert(byte[] gzBytes, int maxItems) throws IOException {
        int vendorsUpserted = 0;
        int productsUpserted = 0;
        int cpeParsed = 0;

        try (InputStream bin = new ByteArrayInputStream(gzBytes);
             GZIPInputStream gin = new GZIPInputStream(bin);
             JsonParser p = jsonFactory.createParser(gin)) {

            while (p.nextToken() != null) {
                if (p.currentToken() != JsonToken.FIELD_NAME) continue;

                String field = p.currentName();
                JsonToken v = p.nextToken();

                if (v == JsonToken.VALUE_STRING && "cpe23Uri".equals(field)) {
                    String cpe23 = p.getValueAsString();
                    cpeParsed++;
                    if (cpeParsed > maxItems) break;

                    Optional<CpeNameParser.VendorProduct> vpOpt = cpeNameParser.parseVendorProduct(cpe23);
                    if (vpOpt.isEmpty()) continue;

                    String vendorKey = vpOpt.get().vendor();
                    String productKey = vpOpt.get().product();

                    // vendor upsert (name_norm)
                    CpeVendor vendor = vendorRepository.findByNameNorm(vendorKey)
                            .orElseGet(() -> new CpeVendor(vendorKey, null));

                    boolean vendorIsNew = (vendor.getId() == null);
                    vendorRepository.save(vendor);
                    if (vendorIsNew) vendorsUpserted++;

                    // product upsert (vendor_id + name_norm)
                    Long vendorId = vendor.getId();
                    if (vendorId == null) continue;

                    boolean prodExists = productRepository.existsByVendorIdAndNameNorm(vendorId, productKey);
                    if (!prodExists) {
                        productRepository.save(new CpeProduct(vendor, productKey, null));
                        productsUpserted++;
                    }
                }
            }
        }

        return new ParseUpsertResult(vendorsUpserted, productsUpserted, cpeParsed);
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }

    private record ParseUpsertResult(int vendorsUpserted, int productsUpserted, int cpeParsed) {
    }

    public record SyncResult(
            boolean skipped,
            int vendorsUpserted,
            int productsUpserted,
            int cpeParsed,
            String metaSha256,
            String metaLastModified,
            Long metaSize
    ) {
        public static SyncResult skipped(String sha256, String lastModified, Long size) {
            return new SyncResult(true, 0, 0, 0, sha256, lastModified, size);
        }

        public static SyncResult executed(int vUp, int pUp, int parsed, String sha256, String lastModified, Long size) {
            return new SyncResult(false, vUp, pUp, parsed, sha256, lastModified, size);
        }
    }
}
