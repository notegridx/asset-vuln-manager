package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class AdminCpeSyncService {

    private static final int MIN_MAX_ITEMS = 1;
    private static final int MAX_MAX_ITEMS = 5_000_000;

    private final CpeFeedSyncService cpeFeedSyncService;
    private final AdminRunRecorder runRecorder;

    public AdminCpeSyncService(
            CpeFeedSyncService cpeFeedSyncService,
            AdminRunRecorder runRecorder
    ) {
        this.cpeFeedSyncService = cpeFeedSyncService;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public CpeFeedSyncService.SyncResult runSync(boolean force, int maxItems) throws IOException {

        int safeMax = clampMaxItems(maxItems);

        try {
            return runRecorder.runExclusive(
                    AdminJobType.CPE_SYNC,
                    Map.of(
                            "sourceMode", "DOWNLOAD",
                            "force", force,
                            "maxItems", safeMax
                    ),
                    "Product dictionary update is already running. Wait for the current run to finish.",
                    () -> cpeFeedSyncService.sync(force, safeMax),
                    this::buildDownloadSummary
            );
        } catch (Exception ex) {
            throw rethrow(ex);
        }
    }

    @Transactional
    public CpeFeedSyncService.SyncResult runSyncFromUpload(MultipartFile file, int maxItems) throws IOException {

        int safeMax = clampMaxItems(maxItems);

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Please select a .tar.gz file to upload.");
        }

        String originalFilename = file.getOriginalFilename();
        String lowerFilename = originalFilename == null ? "" : originalFilename.trim().toLowerCase();

        if (!(lowerFilename.endsWith(".tar.gz") || lowerFilename.endsWith(".tgz"))) {
            throw new IllegalArgumentException("Uploaded file must be a .tar.gz archive.");
        }

        try {
            return runRecorder.runExclusive(
                    AdminJobType.CPE_SYNC,
                    Map.of(
                            "sourceMode", "UPLOAD",
                            "originalFilename", originalFilename == null ? "" : originalFilename,
                            "maxItems", safeMax
                    ),
                    "Product dictionary update is already running. Wait for the current run to finish.",
                    () -> cpeFeedSyncService.syncFromUploadedTarGz(file.getInputStream(), originalFilename, safeMax),
                    this::buildUploadSummary
            );
        } catch (Exception ex) {
            throw rethrow(ex);
        }
    }

    private int clampMaxItems(int maxItems) {
        return Math.max(MIN_MAX_ITEMS, Math.min(maxItems, MAX_MAX_ITEMS));
    }

    private RuntimeException rethrow(Exception ex) throws IOException {
        if (ex instanceof IOException ioEx) {
            throw ioEx;
        }
        if (ex instanceof RuntimeException runtimeEx) {
            return runtimeEx;
        }
        return new RuntimeException(ex);
    }

    private Map<String, Object> buildDownloadSummary(CpeFeedSyncService.SyncResult result) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("sourceMode", "DOWNLOAD");
        summary.put("skipped", result.skipped());
        summary.put("vendorsInserted", result.vendorsInserted());
        summary.put("productsInserted", result.productsInserted());
        summary.put("cpeParsed", result.cpeParsed());
        summary.put("elapsedMs", result.elapsedMs());
        summary.put("elapsedSec", result.elapsedSec());
        summary.put("rowsPerSec", result.rowsPerSec());
        summary.put("metaSha256", result.metaSha256());
        summary.put("metaLastModified", result.metaLastModified());
        summary.put("metaSize", result.metaSize());
        return summary;
    }

    private Map<String, Object> buildUploadSummary(CpeFeedSyncService.SyncResult result) {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("sourceMode", "UPLOAD");
        summary.put("skipped", result.skipped());
        summary.put("vendorsInserted", result.vendorsInserted());
        summary.put("productsInserted", result.productsInserted());
        summary.put("cpeParsed", result.cpeParsed());
        summary.put("elapsedMs", result.elapsedMs());
        summary.put("elapsedSec", result.elapsedSec());
        summary.put("rowsPerSec", result.rowsPerSec());
        return summary;
    }
}