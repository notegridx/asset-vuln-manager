package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.SystemSetting;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class AdminScheduleService {

    public static final String KEY_CVE_DELTA_ENABLED = "schedule.cveDelta.enabled";
    public static final String KEY_CVE_DELTA_INTERVAL_HOURS = "schedule.cveDelta.intervalHours";
    public static final String KEY_CVE_DELTA_DAYS_BACK = "schedule.cveDelta.daysBack";
    public static final String KEY_CVE_DELTA_MAX_RESULTS = "schedule.cveDelta.maxResults";
    public static final String KEY_CVE_DELTA_NEXT_RUN_AT = "schedule.cveDelta.nextRunAt";
    public static final String KEY_CVE_DELTA_LAST_RUN_AT = "schedule.cveDelta.lastRunAt";
    public static final String KEY_CVE_DELTA_LAST_STATUS = "schedule.cveDelta.lastStatus";

    public static final String KEY_GENERATE_ALERTS_ENABLED = "schedule.generateAlerts.enabled";
    public static final String KEY_GENERATE_ALERTS_INTERVAL_HOURS = "schedule.generateAlerts.intervalHours";
    public static final String KEY_GENERATE_ALERTS_NEXT_RUN_AT = "schedule.generateAlerts.nextRunAt";
    public static final String KEY_GENERATE_ALERTS_LAST_RUN_AT = "schedule.generateAlerts.lastRunAt";
    public static final String KEY_GENERATE_ALERTS_LAST_STATUS = "schedule.generateAlerts.lastStatus";

    private static final int DEFAULT_INTERVAL_HOURS = 24;
    private static final int DEFAULT_DAYS_BACK = 1;
    private static final int DEFAULT_MAX_RESULTS = 200;

    private static final String UPDATED_BY_UI = "schedule-ui";
    private static final String UPDATED_BY_SCHEDULER = "schedule-runner";
    private static final String UPDATED_BY_MANUAL = "manual-sync";

    private final SystemSettingRepository systemSettingRepository;

    public AdminScheduleService(SystemSettingRepository systemSettingRepository) {
        this.systemSettingRepository = systemSettingRepository;
    }

    @Transactional(readOnly = true)
    public CveDeltaScheduleView getCveDeltaSchedule() {
        return new CveDeltaScheduleView(
                getBool(KEY_CVE_DELTA_ENABLED, false),
                getInt(KEY_CVE_DELTA_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS),
                getInt(KEY_CVE_DELTA_DAYS_BACK, DEFAULT_DAYS_BACK),
                getInt(KEY_CVE_DELTA_MAX_RESULTS, DEFAULT_MAX_RESULTS),
                getDateTime(KEY_CVE_DELTA_NEXT_RUN_AT),
                getDateTime(KEY_CVE_DELTA_LAST_RUN_AT),
                getString(KEY_CVE_DELTA_LAST_STATUS)
        );
    }

    @Transactional
    public CveDeltaScheduleView saveCveDeltaSchedule(
            boolean enabled,
            int intervalHours,
            int daysBack,
            int maxResults
    ) {
        validateCveDelta(intervalHours, daysBack, maxResults);

        LocalDateTime now = DbTime.now();
        LocalDateTime nextRunAt = enabled ? now.plusHours(intervalHours) : null;

        putBool(KEY_CVE_DELTA_ENABLED, enabled, UPDATED_BY_UI);
        putInt(KEY_CVE_DELTA_INTERVAL_HOURS, intervalHours, UPDATED_BY_UI);
        putInt(KEY_CVE_DELTA_DAYS_BACK, daysBack, UPDATED_BY_UI);
        putInt(KEY_CVE_DELTA_MAX_RESULTS, maxResults, UPDATED_BY_UI);
        putDateTime(KEY_CVE_DELTA_NEXT_RUN_AT, nextRunAt, UPDATED_BY_UI);

        return new CveDeltaScheduleView(
                enabled,
                intervalHours,
                daysBack,
                maxResults,
                nextRunAt,
                getDateTime(KEY_CVE_DELTA_LAST_RUN_AT),
                getString(KEY_CVE_DELTA_LAST_STATUS)
        );
    }

    @Transactional
    public void markSuccess() {
        CveDeltaScheduleView current = getCveDeltaSchedule();
        LocalDateTime now = DbTime.now();

        putDateTime(KEY_CVE_DELTA_LAST_RUN_AT, now, UPDATED_BY_SCHEDULER);
        putString(KEY_CVE_DELTA_LAST_STATUS, "SUCCESS", UPDATED_BY_SCHEDULER);
        putDateTime(
                KEY_CVE_DELTA_NEXT_RUN_AT,
                current.enabled() ? now.plusHours(current.intervalHours()) : null,
                UPDATED_BY_SCHEDULER
        );
    }

    @Transactional
    public void markFailure() {
        CveDeltaScheduleView current = getCveDeltaSchedule();
        LocalDateTime now = DbTime.now();

        putDateTime(KEY_CVE_DELTA_LAST_RUN_AT, now, UPDATED_BY_SCHEDULER);
        putString(KEY_CVE_DELTA_LAST_STATUS, "FAILED", UPDATED_BY_SCHEDULER);
        putDateTime(
                KEY_CVE_DELTA_NEXT_RUN_AT,
                current.enabled() ? now.plusHours(current.intervalHours()) : null,
                UPDATED_BY_SCHEDULER
        );
    }

    @Transactional
    public void touchAfterManualRun() {
        CveDeltaScheduleView current = getCveDeltaSchedule();
        LocalDateTime now = DbTime.now();

        putDateTime(KEY_CVE_DELTA_LAST_RUN_AT, now, UPDATED_BY_MANUAL);
        putString(KEY_CVE_DELTA_LAST_STATUS, "SUCCESS", UPDATED_BY_MANUAL);

        if (current.enabled()) {
            putDateTime(
                    KEY_CVE_DELTA_NEXT_RUN_AT,
                    now.plusHours(current.intervalHours()),
                    UPDATED_BY_MANUAL
            );
        }
    }

    @Transactional(readOnly = true)
    public GenerateAlertsScheduleView getGenerateAlertsSchedule() {
        return new GenerateAlertsScheduleView(
                getBool(KEY_GENERATE_ALERTS_ENABLED, false),
                getInt(KEY_GENERATE_ALERTS_INTERVAL_HOURS, DEFAULT_INTERVAL_HOURS),
                getDateTime(KEY_GENERATE_ALERTS_NEXT_RUN_AT),
                getDateTime(KEY_GENERATE_ALERTS_LAST_RUN_AT),
                getString(KEY_GENERATE_ALERTS_LAST_STATUS)
        );
    }

    @Transactional
    public GenerateAlertsScheduleView saveGenerateAlertsSchedule(
            boolean enabled,
            int intervalHours
    ) {
        validateGenerateAlerts(intervalHours);

        LocalDateTime now = DbTime.now();
        LocalDateTime nextRunAt = enabled ? now.plusHours(intervalHours) : null;

        putBool(KEY_GENERATE_ALERTS_ENABLED, enabled, UPDATED_BY_UI);
        putInt(KEY_GENERATE_ALERTS_INTERVAL_HOURS, intervalHours, UPDATED_BY_UI);
        putDateTime(KEY_GENERATE_ALERTS_NEXT_RUN_AT, nextRunAt, UPDATED_BY_UI);

        return new GenerateAlertsScheduleView(
                enabled,
                intervalHours,
                nextRunAt,
                getDateTime(KEY_GENERATE_ALERTS_LAST_RUN_AT),
                getString(KEY_GENERATE_ALERTS_LAST_STATUS)
        );
    }

    @Transactional
    public void markGenerateAlertsSuccess() {
        GenerateAlertsScheduleView current = getGenerateAlertsSchedule();
        LocalDateTime now = DbTime.now();

        putDateTime(KEY_GENERATE_ALERTS_LAST_RUN_AT, now, UPDATED_BY_SCHEDULER);
        putString(KEY_GENERATE_ALERTS_LAST_STATUS, "SUCCESS", UPDATED_BY_SCHEDULER);
        putDateTime(
                KEY_GENERATE_ALERTS_NEXT_RUN_AT,
                current.enabled() ? now.plusHours(current.intervalHours()) : null,
                UPDATED_BY_SCHEDULER
        );
    }

    @Transactional
    public void markGenerateAlertsFailure() {
        GenerateAlertsScheduleView current = getGenerateAlertsSchedule();
        LocalDateTime now = DbTime.now();

        putDateTime(KEY_GENERATE_ALERTS_LAST_RUN_AT, now, UPDATED_BY_SCHEDULER);
        putString(KEY_GENERATE_ALERTS_LAST_STATUS, "FAILED", UPDATED_BY_SCHEDULER);
        putDateTime(
                KEY_GENERATE_ALERTS_NEXT_RUN_AT,
                current.enabled() ? now.plusHours(current.intervalHours()) : null,
                UPDATED_BY_SCHEDULER
        );
    }

    @Transactional
    public void touchGenerateAlertsAfterManualRun() {
        GenerateAlertsScheduleView current = getGenerateAlertsSchedule();
        LocalDateTime now = DbTime.now();

        putDateTime(KEY_GENERATE_ALERTS_LAST_RUN_AT, now, UPDATED_BY_MANUAL);
        putString(KEY_GENERATE_ALERTS_LAST_STATUS, "SUCCESS", UPDATED_BY_MANUAL);

        if (current.enabled()) {
            putDateTime(
                    KEY_GENERATE_ALERTS_NEXT_RUN_AT,
                    now.plusHours(current.intervalHours()),
                    UPDATED_BY_MANUAL
            );
        }
    }

    private void validateCveDelta(int intervalHours, int daysBack, int maxResults) {
        if (intervalHours < 1 || intervalHours > 24) {
            throw new IllegalArgumentException("Interval hours must be between 1 and 24.");
        }
        if (daysBack < 1 || daysBack > 30) {
            throw new IllegalArgumentException("Days back must be between 1 and 30.");
        }
        if (maxResults < 1 || maxResults > 2000) {
            throw new IllegalArgumentException("Max results must be between 1 and 2000.");
        }
    }

    private void validateGenerateAlerts(int intervalHours) {
        if (intervalHours < 1 || intervalHours > 24) {
            throw new IllegalArgumentException("Interval hours must be between 1 and 24.");
        }
    }

    private boolean getBool(String key, boolean defaultValue) {
        String raw = getRaw(key);
        if (raw == null) {
            return defaultValue;
        }
        return "true".equalsIgnoreCase(raw);
    }

    private int getInt(String key, int defaultValue) {
        String raw = getRaw(key);
        if (raw == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(raw);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private String getString(String key) {
        String raw = getRaw(key);
        return (raw == null || raw.isBlank()) ? null : raw;
    }

    private LocalDateTime getDateTime(String key) {
        String raw = getRaw(key);
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return DbTime.normalize(LocalDateTime.parse(raw));
        } catch (Exception e) {
            return null;
        }
    }

    private String getRaw(String key) {
        return systemSettingRepository.findById(key)
                .map(SystemSetting::getSettingValue)
                .orElse(null);
    }

    private void putBool(String key, boolean value, String updatedBy) {
        putString(key, String.valueOf(value), updatedBy);
    }

    private void putInt(String key, int value, String updatedBy) {
        putString(key, String.valueOf(value), updatedBy);
    }

    private void putDateTime(String key, LocalDateTime value, String updatedBy) {
        putString(key, value == null ? "" : DbTime.normalize(value).toString(), updatedBy);
    }

    private void putString(String key, String value, String updatedBy) {
        SystemSetting setting = systemSettingRepository.findById(key)
                .orElseGet(() -> SystemSetting.of(key, value, updatedBy));
        setting.updateValue(value, updatedBy);
        systemSettingRepository.save(setting);
    }

    public record CveDeltaScheduleView(
            boolean enabled,
            int intervalHours,
            int daysBack,
            int maxResults,
            LocalDateTime nextRunAt,
            LocalDateTime lastRunAt,
            String lastStatus
    ) {
    }

    public record GenerateAlertsScheduleView(
            boolean enabled,
            int intervalHours,
            LocalDateTime nextRunAt,
            LocalDateTime lastRunAt,
            String lastStatus
    ) {
    }
}