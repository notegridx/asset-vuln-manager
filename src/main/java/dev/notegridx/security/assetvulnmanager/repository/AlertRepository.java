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

	// ---- Option C: drilldown filters ----

	// Asset配下のアラート（statusあり）
	List<Alert> findByStatusAndSoftwareInstall_Asset_IdOrderByLastSeenAtDesc(
			AlertStatus status, Long assetId
	);

	// Asset配下のアラート（statusなし = ALL）
	List<Alert> findBySoftwareInstall_Asset_IdOrderByLastSeenAtDesc(Long assetId);
}