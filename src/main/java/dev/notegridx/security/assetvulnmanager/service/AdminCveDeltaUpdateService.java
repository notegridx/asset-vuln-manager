package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.AdminSyncRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminSyncRunRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Map;

@Service
public class AdminCveDeltaUpdateService {

    private static final Logger log = LoggerFactory.getLogger(AdminCveDeltaUpdateService.class);

    private final NvdImportService nvdImportService;
    private final AdminSyncRunRepository syncRunRepository;
    private final AdminRunRecorder runRecorder;

    public AdminCveDeltaUpdateService(
            NvdImportService nvdImportService,
            AdminSyncRunRepository syncRunRepository,
            AdminRunRecorder runRecorder
    ) {
        this.nvdImportService = nvdImportService;
        this.syncRunRepository = syncRunRepository;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public DeltaUpdateResult runDeltaUpdate(int daysBack, int maxResults) {

        var run = runRecorder.start(
                AdminJobType.CVE_DELTA_UPDATE,
                Map.of(
                        "daysBack", daysBack,
                        "maxResults", maxResults
                )
        );

        LocalDateTime ranAt = LocalDateTime.now();

        try {
            int safeDays = Math.max(1, Math.min(daysBack, 120));
            int safeMax = Math.max(1, Math.min(maxResults, 2000));

            OffsetDateTime end = OffsetDateTime.now();
            OffsetDateTime start = end.minusDays(safeDays);

            var importResult = nvdImportService.importFromNvd(start, end, safeMax);

            var result = new DeltaUpdateResult(
                    importResult.vulnerabilitiesUpserted(),
                    importResult.affectedCpesInserted(),
                    importResult.fetched()
            );

            // --- AdminSyncRun (既存専用ログ)
            var syncRun = AdminSyncRun.success(
                    ranAt,
                    safeDays,
                    safeMax,
                    (long) importResult.vulnerabilitiesUpserted(),
                    (long) importResult.affectedCpesInserted(),
                    (long) importResult.fetched(),
                    0L,
                    0L
            );
            syncRunRepository.save(syncRun);

            // --- AdminRun (統合ログ)
            runRecorder.success(run, Map.of(
                    "vulnerabilitiesUpserted", result.vulnerabilitiesUpserted(),
                    "affectedCpesInserted", result.affectedCpesInserted(),
                    "fetched", result.fetched()
            ));

            log.info("CVE delta update completed.");

            return result;

        } catch (Exception ex) {

            var failed = AdminSyncRun.failed(
                    ranAt,
                    daysBack,
                    maxResults,
                    ex.getMessage()
            );
            syncRunRepository.save(failed);

            runRecorder.failed(run, ex);

            throw ex;
        }
    }

    public record DeltaUpdateResult(
            int vulnerabilitiesUpserted,
            int affectedCpesInserted,
            int fetched
    ) {}
}