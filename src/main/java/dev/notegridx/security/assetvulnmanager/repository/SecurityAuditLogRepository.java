package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.SecurityAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface SecurityAuditLogRepository extends JpaRepository<SecurityAuditLog, Long> {

    @Query("""
            select l
            from SecurityAuditLog l
            where (:eventType is null or :eventType = '' or lower(l.eventType) = lower(:eventType))
              and (
                    :q is null or :q = ''
                    or lower(l.eventType) like lower(concat('%', :q, '%'))
                    or lower(coalesce(l.actorUsername, '')) like lower(concat('%', :q, '%'))
                    or lower(coalesce(l.targetUsername, '')) like lower(concat('%', :q, '%'))
                    or lower(l.result) like lower(concat('%', :q, '%'))
                    or lower(coalesce(l.ipAddress, '')) like lower(concat('%', :q, '%'))
                  )
            """)
    Page<SecurityAuditLog> search(
            @Param("eventType") String eventType,
            @Param("q") String q,
            Pageable pageable
    );

    @Query("""
            select distinct l.eventType
            from SecurityAuditLog l
            order by l.eventType asc
            """)
    List<String> findDistinctEventTypes();
}