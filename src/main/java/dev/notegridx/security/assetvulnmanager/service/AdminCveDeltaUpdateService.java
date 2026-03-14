package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

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

    public DeltaUpdateResult runDeltaUpdate(int daysBack, int maxResults) {

        int safeDays = Math.max(1, Math.min(daysBack, 120));
        int safeMax = Math.max(1, Math.min(maxResults, 2000));

        try {
            DeltaUpdateResult result = runRecorder.runExclusive(
                    AdminJobType.CVE_DELTA_UPDATE,
                    Map.of(
                            "daysBack", safeDays,
                            "maxResults", safeMax
                    ),
                    "CVE delta update is already running. Wait for the current run to finish.",
                    () -> {
                        OffsetDateTime end = OffsetDateTime.now();
                        OffsetDateTime start = end.minusDays(safeDays);

                        var importResult = nvdImportService.importFromNvd(start, end, safeMax);

                        return new DeltaUpdateResult(
                                importResult.vulnerabilitiesUpserted(),
                                importResult.affectedCpesInserted(),
                                importResult.fetched()
                        );
                    },
                    r -> Map.of(
                            "vulnerabilitiesUpserted", r.vulnerabilitiesUpserted(),
                            "affectedCpesInserted", r.affectedCpesInserted(),
                            "fetched", r.fetched()
                    )
            );

            log.info("CVE delta update completed.");
            return result;

        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public record DeltaUpdateResult(
            int vulnerabilitiesUpserted,
            int affectedCpesInserted,
            int fetched
    ) {}
}