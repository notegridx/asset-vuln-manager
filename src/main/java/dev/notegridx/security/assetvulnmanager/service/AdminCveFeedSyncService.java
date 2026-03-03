package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class AdminCveFeedSyncService {

    private final CveFeedSyncService cveFeedSyncService;
    private final AdminRunRecorder runRecorder;

    public AdminCveFeedSyncService(
            CveFeedSyncService cveFeedSyncService,
            AdminRunRecorder runRecorder
    ) {
        this.cveFeedSyncService = cveFeedSyncService;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public CveFeedSyncService.SyncResult runSync(
            NvdCveFeedClient.FeedKind kind,
            Integer year,
            boolean force,
            int maxItems
    ) throws IOException {

        int safeMax = Math.max(1, Math.min(maxItems, 5_000_000));

        // Map.of は null NG なので使わない
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("kind", kind.name());
        params.put("year", year);         // null OK
        params.put("force", force);
        params.put("maxItems", safeMax);

        var run = runRecorder.start(AdminJobType.CVE_FEED_SYNC, params);

        try {
            var result = cveFeedSyncService.sync(kind, year, force, safeMax);

            Map<String, Object> res = new LinkedHashMap<>();
            res.put("skipped", result.skipped());
            res.put("vulnerabilitiesUpserted", result.vulnerabilitiesUpserted());
            res.put("affectedCpesInserted", result.affectedCpesInserted());
            res.put("vulnerabilitiesParsed", result.vulnerabilitiesParsed());
            res.put("metaSha256", result.metaSha256());               // null OK
            res.put("metaLastModified", result.metaLastModified());   // null OK
            res.put("metaSize", result.metaSize());                   // null OK

            runRecorder.success(run, res);

            return result;

        } catch (Exception ex) {
            runRecorder.failed(run, ex);
            throw ex;
        }
    }
}