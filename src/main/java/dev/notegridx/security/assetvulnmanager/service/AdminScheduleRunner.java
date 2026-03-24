package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Component
public class AdminScheduleRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminScheduleRunner.class);

    private final AdminScheduleService adminScheduleService;
    private final AdminCveDeltaUpdateService adminCveDeltaUpdateService;
    private final AdminAlertsRecalculateService adminAlertsRecalculateService;

    public AdminScheduleRunner(
            AdminScheduleService adminScheduleService,
            AdminCveDeltaUpdateService adminCveDeltaUpdateService,
            AdminAlertsRecalculateService adminAlertsRecalculateService
    ) {
        this.adminScheduleService = adminScheduleService;
        this.adminCveDeltaUpdateService = adminCveDeltaUpdateService;
        this.adminAlertsRecalculateService = adminAlertsRecalculateService;
    }

    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void runCveDeltaIfDue() {
        AdminScheduleService.CveDeltaScheduleView schedule = adminScheduleService.getCveDeltaSchedule();

        if (!schedule.enabled()) {
            return;
        }
        if (schedule.nextRunAt() == null) {
            return;
        }

        LocalDateTime now = DbTime.now();
        if (now.isBefore(schedule.nextRunAt())) {
            return;
        }

        try {
            log.info(
                    "Scheduled CVE delta update started. daysBack={}, maxResults={}, nextRunAt={}",
                    schedule.daysBack(),
                    schedule.maxResults(),
                    schedule.nextRunAt()
            );

            adminCveDeltaUpdateService.runDeltaUpdate(
                    schedule.daysBack(),
                    schedule.maxResults()
            );

            adminScheduleService.markSuccess();

            log.info("Scheduled CVE delta update completed successfully.");

        } catch (AdminJobAlreadyRunningException ex) {
            log.info("Scheduled CVE delta update skipped because the job is already running: {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("Scheduled CVE delta update failed.", ex);
            adminScheduleService.markFailure();
        }
    }

    @Scheduled(fixedDelay = 60_000)
    @Transactional
    public void runGenerateAlertsIfDue() {
        AdminScheduleService.GenerateAlertsScheduleView schedule = adminScheduleService.getGenerateAlertsSchedule();

        if (!schedule.enabled()) {
            return;
        }
        if (schedule.nextRunAt() == null) {
            return;
        }

        LocalDateTime now = DbTime.now();
        if (now.isBefore(schedule.nextRunAt())) {
            return;
        }

        try {
            log.info(
                    "Scheduled Generate Alerts started. nextRunAt={}",
                    schedule.nextRunAt()
            );

            adminAlertsRecalculateService.runRecalculate();

            adminScheduleService.markGenerateAlertsSuccess();

            log.info("Scheduled Generate Alerts completed successfully.");

        } catch (AdminJobAlreadyRunningException ex) {
            log.info("Scheduled Generate Alerts skipped because the job is already running: {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("Scheduled Generate Alerts failed.", ex);
            adminScheduleService.markGenerateAlertsFailure();
        }
    }
}