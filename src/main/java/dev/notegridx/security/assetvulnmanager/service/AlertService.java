package dev.notegridx.security.assetvulnmanager.service;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

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

    @Transactional(readOnly = true)
    public List<Alert> findByStatus(AlertStatus status) {
        return alertRepository.findByStatusOrderByLastSeenAtDesc(status);
    }

    @Transactional(readOnly = true)
    public List<Alert> findAll() {
        return alertRepository.findAll()
                .stream()
                .sorted((a, b) -> b.getLastSeenAt().compareTo(a.getLastSeenAt()))
                .toList();
    }

    @Transactional(readOnly = true)
    public Alert getRequired(Long id) {
        return alertRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Alert not found. id=" + id));
    }

    @Transactional
    public Alert close(Long alertId, CloseReason reason) {
        if (reason == null) {
            throw new IllegalArgumentException("close reason is required");
        }

        Alert alert = getRequired(alertId);

        if (alert.getStatus() == AlertStatus.CLOSED) {
            return alert;
        }

        alert.close(reason, LocalDateTime.now());
        return alertRepository.save(alert);
    }

    public List<String> listFilterKeys() {
        return Arrays.asList("OPEN", "CLOSED", "ALL");
    }
}
