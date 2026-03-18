package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.SecurityAuditLog;
import dev.notegridx.security.assetvulnmanager.repository.SecurityAuditLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecurityAuditService {

    private final SecurityAuditLogRepository securityAuditLogRepository;

    public SecurityAuditService(SecurityAuditLogRepository securityAuditLogRepository) {
        this.securityAuditLogRepository = securityAuditLogRepository;
    }

    @Transactional
    public void log(
            String eventType,
            String actorUsername,
            String targetUsername,
            String result,
            String ipAddress,
            String message
    ) {
        securityAuditLogRepository.save(
                SecurityAuditLog.of(eventType, actorUsername, targetUsername, result, ipAddress, message)
        );
    }
}