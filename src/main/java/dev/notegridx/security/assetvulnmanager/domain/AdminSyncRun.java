package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;

@Entity
@Table(
        name = "admin_sync_runs",
        indexes = {
                @Index(name = "idx_admin_sync_runs_ran_at", columnList = "ran_at")
        }
)
@Getter
public class AdminSyncRun {

    public enum Status {
        SUCCESS, FAILED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ran_at", nullable = false)
    private LocalDateTime ranAt;

    @Column(name = "days_back")
    private Integer daysBack;

    @Column(name = "max_results")
    private Integer maxResults;

    @Column(name = "vulnerabilities_upserted")
    private Long vulnerabilitiesUpserted;

    @Column(name = "affected_cpes_upserted")
    private Long affectedCpesUpserted;

    @Column(name = "pairs_found")
    private Long pairsFound;

    @Column(name = "alerts_inserted")
    private Long alertsInserted;

    @Column(name = "alerts_touched")
    private Long alertsTouched;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private Status status = Status.SUCCESS;

    @Column(name = "error_message", length = 1024)
    private String errorMessage;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected AdminSyncRun() {}

    public static AdminSyncRun success(
            LocalDateTime ranAt,
            Integer daysBack,
            Integer maxResults,
            Long vulnerabilitiesUpserted,
            Long affectedCpesUpserted,
            Long pairsFound,
            Long alertsInserted,
            Long alertsTouched
    ) {
        AdminSyncRun r = new AdminSyncRun();
        r.ranAt = ranAt;
        r.daysBack = daysBack;
        r.maxResults = maxResults;
        r.vulnerabilitiesUpserted = nz(vulnerabilitiesUpserted);
        r.affectedCpesUpserted = nz(affectedCpesUpserted);
        r.pairsFound = nz(pairsFound);
        r.alertsInserted = nz(alertsInserted);
        r.alertsTouched = nz(alertsTouched);
        r.status = Status.SUCCESS;
        return r;
    }

    public static AdminSyncRun failed(LocalDateTime ranAt, Integer daysBack, Integer maxResults, String errorMessage) {
        AdminSyncRun r = new AdminSyncRun();
        r.ranAt = ranAt;
        r.daysBack = daysBack;
        r.maxResults = maxResults;
        r.status = Status.FAILED;
        r.errorMessage = (errorMessage == null) ? null : errorMessage.trim();
        r.vulnerabilitiesUpserted = 0L;
        r.affectedCpesUpserted = 0L;
        r.pairsFound = 0L;
        r.alertsInserted = 0L;
        r.alertsTouched = 0L;
        return r;
    }

    private static long nz(Long v) {
        return v == null ? 0L : v;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = DbTime.now();
    }
}
