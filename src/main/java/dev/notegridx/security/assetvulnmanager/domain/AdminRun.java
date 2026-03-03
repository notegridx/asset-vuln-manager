package dev.notegridx.security.assetvulnmanager.domain;

import java.time.Duration;
import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminRunStatus;
import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(
        name = "admin_runs",
        indexes = {
                @Index(name = "idx_admin_runs_started_at", columnList = "started_at"),
                @Index(name = "idx_admin_runs_job_type", columnList = "job_type"),
                @Index(name = "idx_admin_runs_status", columnList = "status")
        }
)
@Getter
public class AdminRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "job_type", nullable = false, length = 64)
    private AdminJobType jobType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private AdminRunStatus status;

    @Column(name = "started_at", nullable = false)
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;

    @Column(name = "duration_ms")
    private Long durationMs;

    @Lob
    @Column(name = "params_json")
    private String paramsJson;

    @Lob
    @Column(name = "result_json")
    private String resultJson;

    @Lob
    @Column(name = "error_message")
    private String errorMessage;

    @Column(nullable = false, name = "created_at")
    private LocalDateTime createdAt;

    @Column(nullable = false, name = "updated_at")
    private LocalDateTime updatedAt;

    protected AdminRun() {
    }

    public static AdminRun start(AdminJobType jobType, String paramsJson) {
        if (jobType == null) throw new IllegalArgumentException("jobType is required");

        AdminRun r = new AdminRun();
        LocalDateTime now = DbTime.now();

        r.jobType = jobType;
        r.status = AdminRunStatus.RUNNING;
        r.startedAt = now;
        r.paramsJson = paramsJson;

        r.createdAt = now;
        r.updatedAt = now;
        return r;
    }

    public void markSuccess(String resultJson) {
        LocalDateTime now = DbTime.now();
        this.status = AdminRunStatus.SUCCESS;
        this.finishedAt = now;
        this.resultJson = resultJson;
        this.durationMs = calcDurationMs(this.startedAt, now);
        this.updatedAt = now;
    }

    public void markFailed(String errorMessage) {
        LocalDateTime now = DbTime.now();
        this.status = AdminRunStatus.FAILED;
        this.finishedAt = now;
        this.errorMessage = errorMessage;
        this.durationMs = calcDurationMs(this.startedAt, now);
        this.updatedAt = now;
    }

    public void setParamsJson(String paramsJson) {
        this.paramsJson = paramsJson;
    }

    public void setResultJson(String resultJson) {
        this.resultJson = resultJson;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    @PrePersist
    void onCreate() {
        LocalDateTime now = DbTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
        if (startedAt == null) startedAt = now;
        if (status == null) status = AdminRunStatus.RUNNING;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = DbTime.now();
    }

    private static Long calcDurationMs(LocalDateTime start, LocalDateTime end) {
        if (start == null || end == null) return null;
        long ms = Duration.between(start, end).toMillis();
        return Math.max(0, ms);
    }
}