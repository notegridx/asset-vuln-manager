package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import dev.notegridx.security.assetvulnmanager.domain.Alert;

import java.util.List;

public interface DashboardStatsRepository extends JpaRepository<Alert, Long> {

    interface OpenAlertBreakdownRow {
        Severity getSeverity();
        AlertCertainty getCertainty();
        long getCnt();
    }

    @Query("""
            select
                v.severity as severity,
                a.certainty as certainty,
                count(a) as cnt
            from Alert a
            left join a.vulnerability v
            where a.status = :status
            group by v.severity, a.certainty
            """)
    List<OpenAlertBreakdownRow> aggregateAlertBreakdownBySeverityAndCertainty(
            @Param("status") AlertStatus status
    );
}