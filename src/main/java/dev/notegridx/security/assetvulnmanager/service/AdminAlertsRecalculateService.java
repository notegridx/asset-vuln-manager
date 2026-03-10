package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
public class AdminAlertsRecalculateService {

    private final MatchingService matchingService;
    private final AdminRunRecorder runRecorder;

    public AdminAlertsRecalculateService(
            MatchingService matchingService,
            AdminRunRecorder runRecorder
    ) {
        this.matchingService = matchingService;
        this.runRecorder = runRecorder;
    }

    @Transactional
    public MatchingService.MatchResult runRecalculate() {
        try {
            return runRecorder.runExclusive(
                    AdminJobType.ALERT_RECALCULATE,
                    Map.of(),
                    "Alert generation is already running. Wait for the current run to finish.",
                    matchingService::matchAndUpsertAlerts,
                    result -> Map.of(
                            "pairsFound", result.pairsFound(),
                            "alertsInserted", result.alertsInserted(),
                            "alertsTouched", result.alertsTouched(),
                            "alertsAutoClosed", result.alertsAutoClosed()
                    )
            );
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}