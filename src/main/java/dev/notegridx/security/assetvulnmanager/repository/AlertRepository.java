package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;

public interface AlertRepository extends JpaRepository<Alert, Long> {

	Optional<Alert> findBySoftwareInstallIdAndVulnerabilityId(Long softwareInstallId, Long vulnerabilityId);

	List<Alert> findByStatusOrderByLastSeenAtDesc(AlertStatus status);

	long countByStatus(AlertStatus status);

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
}
