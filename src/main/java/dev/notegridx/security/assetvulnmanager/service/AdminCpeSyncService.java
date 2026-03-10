package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class AdminCpeSyncService {

    private static final AtomicBoolean RUNNING = new AtomicBoolean(false);

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

        if (!RUNNING.compareAndSet(false, true)) {
            throw new AdminJobAlreadyRunningException(
                    "Product dictionary update is already running. Wait for the current run to finish."
            );
        }

        try {
            int safeMax = Math.max(1, Math.min(maxItems, 5_000_000));

            var run = runRecorder.start(
                    AdminJobType.CPE_SYNC,
                    Map.of(
                            "force", force,
                            "maxItems", safeMax
                    )
            );

            try {
                var result = cpeFeedSyncService.sync(force, safeMax);

                runRecorder.success(run, Map.of(
                        "skipped", result.skipped(),
                        "vendorsInserted", result.vendorsInserted(),
                        "productsInserted", result.productsInserted(),
                        "cpeParsed", result.cpeParsed(),
                        "metaSha256", result.metaSha256(),
                        "metaLastModified", result.metaLastModified(),
                        "metaSize", result.metaSize()
                ));

                return result;

            } catch (Exception ex) {
                runRecorder.failed(run, ex);
                throw ex;
            }
        } finally {
            RUNNING.set(false);
        }
    }
}