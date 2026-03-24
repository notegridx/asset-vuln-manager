package dev.notegridx.security.assetvulnmanager.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;

@Component
public class AdminScheduleRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminScheduleRunner.class);

    private final AdminScheduleService adminScheduleService;
    private final AdminCveDeltaUpdateService adminCveDeltaUpdateService;

    public AdminScheduleRunner(
            AdminScheduleService adminScheduleService,
            AdminCveDeltaUpdateService adminCveDeltaUpdateService
    ) {
        this.adminScheduleService = adminScheduleService;
        this.adminCveDeltaUpdateService = adminCveDeltaUpdateService;
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
}