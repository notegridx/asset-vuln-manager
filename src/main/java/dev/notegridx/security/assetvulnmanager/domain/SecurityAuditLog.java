package dev.notegridx.security.assetvulnmanager.domain;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Table(
        name = "security_audit_logs",
        indexes = {
                @Index(name = "idx_security_audit_logs_created_at", columnList = "created_at"),
                @Index(name = "idx_security_audit_logs_event_type", columnList = "event_type"),
                @Index(name = "idx_security_audit_logs_actor_username", columnList = "actor_username"),
                @Index(name = "idx_security_audit_logs_target_username", columnList = "target_username")
        }
)
@Getter
public class SecurityAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "actor_username", length = 100)
    private String actorUsername;

    @Column(name = "target_username", length = 100)
    private String targetUsername;

    @Column(name = "result", nullable = false, length = 32)
    private String result;

    @Column(name = "ip_address", length = 128)
    private String ipAddress;

    @Lob
    @Column(name = "message")
    private String message;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    protected SecurityAuditLog() {
    }

    public static SecurityAuditLog of(
            String eventType,
            String actorUsername,
            String targetUsername,
            String result,
            String ipAddress,
            String message
    ) {
        SecurityAuditLog log = new SecurityAuditLog();
        log.eventType = normalizeRequired(eventType, "eventType");
        log.actorUsername = normalizeNullable(actorUsername);
        log.targetUsername = normalizeNullable(targetUsername);
        log.result = normalizeRequired(result, "result");
        log.ipAddress = normalizeNullable(ipAddress);
        log.message = normalizeNullable(message);
        return log;
    }

    private static String normalizeRequired(String value, String field) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private static String normalizeNullable(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        return v.isEmpty() ? null : v;
    }

    @PrePersist
    void prePersist() {
        this.createdAt = DbTime.now();
    }
}