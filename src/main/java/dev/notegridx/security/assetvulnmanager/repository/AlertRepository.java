package dev.notegridx.security.assetvulnmanager.repository;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    long deleteBySoftwareInstallId(Long softwareInstallId);

    long deleteBySoftwareInstallIdIn(Collection<Long> softwareInstallIds);

    Optional<Alert> findBySoftwareInstallIdAndVulnerabilityId(Long softwareInstallId, Long vulnerabilityId);

    List<Alert> findByStatusOrderByLastSeenAtDesc(AlertStatus status);

    long countByStatus(AlertStatus status);

    // Dashboard: OPEN alerts by severity
    long countByStatusAndVulnerability_Severity(AlertStatus status, Severity severity);

    // Dashboard: OPEN alerts by certainty (CONFIRMED / UNCONFIRMED)
    long countByStatusAndCertainty(AlertStatus status, AlertCertainty certainty);

    // Dashboard: OPEN alerts by severity + certainty
    long countByStatusAndVulnerability_SeverityAndCertainty(AlertStatus status, Severity severity, AlertCertainty certainty);

    List<Alert> findBySoftwareInstallIdOrderByLastSeenAtDesc(Long softwareInstallId);

    // ---- drilldown: by asset ----
    List<Alert> findBySoftwareInstall_Asset_IdOrderByLastSeenAtDesc(Long assetId);

    List<Alert> findByStatusAndSoftwareInstall_Asset_IdOrderByLastSeenAtDesc(AlertStatus status, Long assetId);

    // ---- drilldown: by softwareInstall ----
    List<Alert> findBySoftwareInstall_IdOrderByLastSeenAtDesc(Long softwareInstallId);

    List<Alert> findByStatusAndSoftwareInstall_IdOrderByLastSeenAtDesc(AlertStatus status, Long softwareInstallId);

    // ---- ALL: OPEN+CLOSED ----
    List<Alert> findByStatusInOrderByLastSeenAtDesc(List<AlertStatus> statuses);

    List<Alert> findByStatusInAndSoftwareInstall_Asset_IdOrderByLastSeenAtDesc(List<AlertStatus> statuses, Long assetId);

    List<Alert> findByStatusInAndSoftwareInstall_IdOrderByLastSeenAtDesc(List<AlertStatus> statuses, Long softwareInstallId);

    /**
     * Generate Alerts 実行中に touchDetected() されなかった（= lastSeenAt が runStartedAt より古い）OPEN Alert を自動で CLOSE する。
     *
     * NOTE: JPQL bulk update は @PreUpdate を通らないため、updatedAt も明示的に更新する。
     */
    @Modifying
    @Query("""
        update Alert a
           set a.status = dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus.CLOSED,
               a.closeReason = :reason,
               a.closedAt = :closedAt,
               a.updatedAt = :closedAt
         where a.status = dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus.OPEN
           and a.createdAt < :runStartedAt
           and a.lastSeenAt < :runStartedAt
       """)
    int closeStaleOpenAlerts(
            @Param("runStartedAt") LocalDateTime runStartedAt,
            @Param("reason") CloseReason reason,
            @Param("closedAt") LocalDateTime closedAt
    );

    @Query("""
                select a.softwareInstall.id, count(a)
                from Alert a
                where a.softwareInstall.id in :ids
                group by a.softwareInstall.id
            """)
    List<Object[]> countBySoftwareInstallIds(@Param("ids") List<Long> ids);

    @Query("""
        select a.vulnerability.id, count(a)
        from Alert a
        where a.vulnerability.id in :ids
          and a.status = dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus.OPEN
        group by a.vulnerability.id
    """)
    List<Object[]> countOpenByVulnerabilityIds(@Param("ids") List<Long> ids);
}