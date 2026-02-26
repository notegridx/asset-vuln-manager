package dev.notegridx.security.assetvulnmanager.service;

import java.time.OffsetDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminCveDeltaUpdateService {

    private static final Logger log = LoggerFactory.getLogger(AdminCveDeltaUpdateService.class);

    private final NvdImportService nvdImportService;

    public AdminCveDeltaUpdateService(NvdImportService nvdImportService) {
        this.nvdImportService = nvdImportService;
    }

    @Transactional
    public DeltaUpdateResult runDeltaUpdate(int daysBack, int maxResults) {
        int safeDays = Math.max(1, Math.min(daysBack, 120));
        int safeMax = Math.max(1, Math.min(maxResults, 2000));

        OffsetDateTime end = OffsetDateTime.now();
        OffsetDateTime start = end.minusDays(safeDays);

        var importResult = nvdImportService.importFromNvd(start, end, safeMax);

        log.info("CVE delta update done: fetched={}, vulnUpserted={}, affectedInserted={}",
                importResult.fetched(),
                importResult.vulnerabilitiesUpserted(),
                importResult.affectedCpesInserted());

        return new DeltaUpdateResult(
                importResult.vulnerabilitiesUpserted(),
                importResult.affectedCpesInserted(),
                importResult.fetched()
        );
    }

    public record DeltaUpdateResult(
            int vulnerabilitiesUpserted,
            int affectedCpesInserted,
            int fetched
    ) {}
}