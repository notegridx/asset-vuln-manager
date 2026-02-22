package dev.notegridx.security.assetvulnmanager.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;

import jakarta.persistence.EntityNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;

@Service
public class AlertService {

    private final AlertRepository alertRepository;

    public AlertService(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    /**
     * statusKey: "OPEN" / "CLOSED" / "ALL" / null
     * - null は "OPEN" 扱い（互換）
     * - "ALL" は OPEN + CLOSED
     */
    @Transactional(readOnly = true)
    public List<Alert> list(String statusKey, Long assetId, Long softwareId) {
        String effective = (statusKey == null) ? "OPEN" : statusKey.trim().toUpperCase(Locale.ROOT);

        // drilldown は assetId / softwareId のどちらか片方想定（両方来たら software優先）
        if ("ALL".equals(effective)) {
            List<AlertStatus> statuses = List.of(AlertStatus.OPEN, AlertStatus.CLOSED);

            if (softwareId != null) {
                return alertRepository.findByStatusInAndSoftwareInstall_IdOrderByLastSeenAtDesc(statuses, softwareId);
            }
            if (assetId != null) {
                return alertRepository.findByStatusInAndSoftwareInstall_Asset_IdOrderByLastSeenAtDesc(statuses, assetId);
            }
            return alertRepository.findByStatusInOrderByLastSeenAtDesc(statuses);
        }

        AlertStatus st = "CLOSED".equals(effective) ? AlertStatus.CLOSED : AlertStatus.OPEN;

        if (softwareId != null) {
            return alertRepository.findByStatusAndSoftwareInstall_IdOrderByLastSeenAtDesc(st, softwareId);
        }
        if (assetId != null) {
            return alertRepository.findByStatusAndSoftwareInstall_Asset_IdOrderByLastSeenAtDesc(st, assetId);
        }
        return alertRepository.findByStatusOrderByLastSeenAtDesc(st);
    }

    @Transactional(readOnly = true)
    public Alert getRequired(Long id) {
        return alertRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Alert not found. id=" + id));
    }

    @Transactional
    public Alert close(Long alertId, CloseReason reason) {
        if (reason == null) throw new IllegalArgumentException("close reason is required");

        Alert alert = getRequired(alertId);
        if (alert.getStatus() == AlertStatus.CLOSED) return alert;

        alert.close(reason, LocalDateTime.now());
        return alertRepository.save(alert);
    }
}
