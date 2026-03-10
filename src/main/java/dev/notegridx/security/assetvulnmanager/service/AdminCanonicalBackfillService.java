package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.Map;

@Service
public class AdminCanonicalBackfillService {

    private final CanonicalBackfillService canonicalBackfillService;
    private final SynonymService synonymService;
    private final AdminRunRecorder runRecorder;

    public AdminCanonicalBackfillService(
            CanonicalBackfillService canonicalBackfillService,
            SynonymService synonymService,
            AdminRunRecorder runRecorder
    ) {
        this.canonicalBackfillService = canonicalBackfillService;
        this.synonymService = synonymService;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public CanonicalBackfillService.BackfillResult runBackfill(int maxRows, boolean relink) {

        int safeMax = Math.max(1, Math.min(maxRows, 5_000_000));

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("maxRows", safeMax);
        params.put("relink", relink);

        try {
            return runRecorder.runExclusive(
                    AdminJobType.CANONICAL_BACKFILL,
                    params,
                    "Canonical linking is already running. Wait for the current run to finish.",
                    () -> {
                        synonymService.clearCaches();
                        return canonicalBackfillService.backfill(safeMax, relink);
                    },
                    result -> {
                        Map<String, Object> out = new LinkedHashMap<>();
                        out.put("scanned", result.scanned());
                        out.put("linked", result.linked());
                        out.put("missed", result.missed());
                        out.put("forceRebuild", result.forceRebuild());
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