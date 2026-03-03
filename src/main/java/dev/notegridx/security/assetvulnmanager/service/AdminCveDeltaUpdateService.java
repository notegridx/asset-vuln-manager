package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.Map;

@Service
public class AdminCveDeltaUpdateService {

    private static final Logger log = LoggerFactory.getLogger(AdminCveDeltaUpdateService.class);

    private final NvdImportService nvdImportService;
    private final AdminRunRecorder runRecorder;

    public AdminCveDeltaUpdateService(
            NvdImportService nvdImportService,
            AdminRunRecorder runRecorder
    ) {
        this.nvdImportService = nvdImportService;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public DeltaUpdateResult runDeltaUpdate(int daysBack, int maxResults) {

        int safeDays = Math.max(1, Math.min(daysBack, 120));
        int safeMax = Math.max(1, Math.min(maxResults, 2000));

        var run = runRecorder.start(
                AdminJobType.CVE_DELTA_UPDATE,
                Map.of(
                        "daysBack", safeDays,
                        "maxResults", safeMax
                )
        );

        try {
            OffsetDateTime end = OffsetDateTime.now();
            OffsetDateTime start = end.minusDays(safeDays);

            var importResult = nvdImportService.importFromNvd(start, end, safeMax);

            var result = new DeltaUpdateResult(
                    importResult.vulnerabilitiesUpserted(),
                    importResult.affectedCpesInserted(),
                    importResult.fetched()
            );

            runRecorder.success(run, Map.of(
                    "vulnerabilitiesUpserted", result.vulnerabilitiesUpserted(),
                    "affectedCpesInserted", result.affectedCpesInserted(),
                    "fetched", result.fetched()
            ));

            log.info("CVE delta update completed.");

            return result;

        } catch (Exception ex) {
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