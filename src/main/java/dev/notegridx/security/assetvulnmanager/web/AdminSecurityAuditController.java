package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SecurityAuditLog;
import dev.notegridx.security.assetvulnmanager.repository.SecurityAuditLogRepository;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.LocalDateTime;
import java.util.List;

@Controller
@RequestMapping("/admin/security-audit")
@PreAuthorize("hasRole('ADMIN')")
public class AdminSecurityAuditController {

    private static final int DEFAULT_SIZE = 50;
    private static final int MAX_SIZE = 200;

    private final SecurityAuditLogRepository securityAuditLogRepository;
    private final DemoModeService demoModeService;

    public AdminSecurityAuditController(
            SecurityAuditLogRepository securityAuditLogRepository,
            DemoModeService demoModeService
    ) {
        this.securityAuditLogRepository = securityAuditLogRepository;
        this.demoModeService = demoModeService;
    }

    @GetMapping
    public String list(
            @RequestParam(name = "eventType", required = false) String eventType,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "" + DEFAULT_SIZE) int size,
            Model model
    ) {
        int safePage = Math.max(page, 0);
        int safeSize = normalizeSize(size);

        Pageable pageable = PageRequest.of(
                safePage,
                safeSize,
                Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"))
        );

        String eventTypeFilter = normalize(eventType);
        String query = normalize(q);

        Page<SecurityAuditLog> logs = securityAuditLogRepository.search(eventTypeFilter, query, pageable);
        boolean demoMode = demoModeService.isReadOnly();

        List<AuditLogRow> items = logs.getContent().stream()
                .map(log -> toRow(log, demoMode))
                .toList();

        model.addAttribute("logs", logs);
        model.addAttribute("items", items);
        model.addAttribute("eventTypes", securityAuditLogRepository.findDistinctEventTypes());

        model.addAttribute("eventType", eventTypeFilter);
        model.addAttribute("q", query);

        model.addAttribute("page", logs.getNumber());
        model.addAttribute("size", logs.getSize());
        model.addAttribute("totalPages", logs.getTotalPages());
        model.addAttribute("totalElements", logs.getTotalElements());
        model.addAttribute("hasPrevious", logs.hasPrevious());
        model.addAttribute("hasNext", logs.hasNext());
        model.addAttribute("auditLogSanitized", demoMode);

        return "admin/security_audit";
    }

    private static AuditLogRow toRow(SecurityAuditLog log, boolean demoMode) {
        if (!demoMode) {
            return new AuditLogRow(
                    log.getCreatedAt(),
                    log.getEventType(),
                    blankToDash(log.getActorUsername()),
                    blankToDash(log.getTargetUsername()),
                    blankToDash(log.getResult()),
                    blankToDash(log.getIpAddress()),
                    blankToDash(log.getMessage())
            );
        }

        return new AuditLogRow(
                log.getCreatedAt(),
                log.getEventType(),
                maskUsername(log.getActorUsername()),
                maskUsername(log.getTargetUsername()),
                blankToDash(log.getResult()),
                maskIp(log.getIpAddress()),
                blankToDash(log.getMessage())
        );
    }

    private static String maskUsername(String username) {
        String value = normalize(username);
        if (value == null) {
            return "-";
        }
        if ("demo".equalsIgnoreCase(value)) {
            return "demo";
        }
        return "user";
    }

    private static String maskIp(String ip) {
        String value = normalize(ip);
        if (value == null) {
            return "-";
        }

        if (value.contains(":")) {
            String[] parts = value.split(":", -1);
            if (parts.length <= 2) {
                return "****";
            }
            return parts[0] + ":" + parts[1] + ":****";
        }

        if (value.contains(".")) {
            String[] parts = value.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + ".xxx.xxx";
            }
            return "xxx.xxx.xxx.xxx";
        }

        return "masked";
    }

    private static String blankToDash(String value) {
        String v = normalize(value);
        return v == null ? "-" : v;
    }

    private static int normalizeSize(int size) {
        if (size <= 0) {
            return DEFAULT_SIZE;
        }
        return Math.min(size, MAX_SIZE);
    }

    private static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        return v.isEmpty() ? null : v;
    }

    public record AuditLogRow(
            LocalDateTime createdAt,
            String eventType,
            String actorUsername,
            String targetUsername,
            String result,
            String ipAddress,
            String message
    ) {
    }
}