package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;

public interface AlertRepository extends JpaRepository<Alert, Long> {

	Optional<Alert> findBySoftwareInstallIdAndVulnerabilityId(Long softwareInstallId, Long vulnerabilityId);
	
	List<Alert> findByStatusOrderByLastSeenAtDesc(AlertStatus status);
	
	List<Alert> findBySoftwareInstallIdOrderByLastSeenAtDesc(Long softwareInstallId);
}
