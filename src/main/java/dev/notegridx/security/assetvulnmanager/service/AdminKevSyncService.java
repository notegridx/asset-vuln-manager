package dev.notegridx.security.assetvulnmanager.service;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;

@Service
public class AdminKevSyncService {

    private final KevSyncService kevSyncService;
    private final AdminRunRecorder runRecorder;

    public AdminKevSyncService(KevSyncService kevSyncService, AdminRunRecorder runRecorder) {
        this.kevSyncService = kevSyncService;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public KevSyncService.SyncResult run(boolean force, int maxItems) {

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("force", force);
        params.put("maxItems", maxItems);

        AdminRun run = runRecorder.start(AdminJobType.KEV_SYNC, params);

        try {
            KevSyncService.SyncResult result = kevSyncService.sync(force, maxItems);

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("skippedNotModified", result.skippedNotModified());
            out.put("catalogEntries", result.catalogEntries());
            out.put("processedEntries", result.processedEntries());
            out.put("updatedVulns", result.updatedVulns());
            out.put("missingInDb", result.missingInDb());
            out.put("bodySha256", result.bodySha256());

            runRecorder.success(run, out);
            return result;

        } catch (Exception e) {
            runRecorder.failed(run, e);
            throw e;
        }
    }
}