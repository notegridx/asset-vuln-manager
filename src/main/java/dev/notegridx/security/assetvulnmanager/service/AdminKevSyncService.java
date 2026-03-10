package dev.notegridx.security.assetvulnmanager.service;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

        int safeMax = Math.max(1, Math.min(maxItems, 50_000));

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("force", force);
        params.put("maxItems", safeMax);

        try {
            return runRecorder.runExclusive(
                    AdminJobType.KEV_SYNC,
                    params,
                    "KEV sync is already running. Wait for the current run to finish.",
                    () -> kevSyncService.sync(force, safeMax),
                    result -> {
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("skippedNotModified", result.skippedNotModified());
                        out.put("catalogEntries", result.catalogEntries());
                        out.put("processedEntries", result.processedEntries());
                        out.put("updatedVulns", result.updatedVulns());
                        out.put("missingInDb", result.missingInDb());
                        out.put("bodySha256", result.bodySha256());
                        return out;
                    }
            );
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}