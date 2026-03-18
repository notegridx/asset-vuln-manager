package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.repository.SecurityAuditLogRepository;
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

@Controller
@RequestMapping("/admin/security-audit")
@PreAuthorize("hasRole('ADMIN')")
public class AdminSecurityAuditController {

    private static final int DEFAULT_SIZE = 50;
    private static final int MAX_SIZE = 200;

    private final SecurityAuditLogRepository securityAuditLogRepository;

    public AdminSecurityAuditController(SecurityAuditLogRepository securityAuditLogRepository) {
        this.securityAuditLogRepository = securityAuditLogRepository;
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

        Page<?> logs = securityAuditLogRepository.search(eventTypeFilter, query, pageable);

        model.addAttribute("logs", logs);
        model.addAttribute("items", logs.getContent());
        model.addAttribute("eventTypes", securityAuditLogRepository.findDistinctEventTypes());

        model.addAttribute("eventType", eventTypeFilter);
        model.addAttribute("q", query);

        model.addAttribute("page", logs.getNumber());
        model.addAttribute("size", logs.getSize());
        model.addAttribute("totalPages", logs.getTotalPages());
        model.addAttribute("totalElements", logs.getTotalElements());
        model.addAttribute("hasPrevious", logs.hasPrevious());
        model.addAttribute("hasNext", logs.hasNext());

        return "admin/security_audit";
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
}