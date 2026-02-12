package dev.notegridx.security.assetvulnmanager.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;

@Service
public class MatchingService {

	private final SoftwareInstallRepository softwareInstallRepository;
	private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
	private final VulnerabilityRepository vulnerabilityRepository;
	private final AlertRepository alertRepository;

	public MatchingService(SoftwareInstallRepository softwareInstallRepository,
			VulnerabilityAffectedCpeRepository affectedCpeRepository,
			VulnerabilityRepository vulnerabilityRepository,
			AlertRepository alertRepository) {
		this.softwareInstallRepository = softwareInstallRepository;
		this.affectedCpeRepository = affectedCpeRepository;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.alertRepository = alertRepository;
	}

	@Transactional
	public MatchResult matchAndUpsertAlerts() {
		LocalDateTime now = LocalDateTime.now();

		List<SoftwareInstall> installs = softwareInstallRepository.findByCpeNameIsNotNull();
		List<String> cpes = installs.stream()
				.map(SoftwareInstall::getCpeName)
				.filter(Objects::nonNull)
				.distinct()
				.toList();

		if (cpes.isEmpty()) {
			return new MatchResult(0, 0, 0);
		}

		List<VulnerabilityAffectedCpe> affected = affectedCpeRepository.findByCpeNameIn(cpes);

		Map<String, List<Long>> cpeToVulnIds = affected.stream()
				.collect(Collectors.groupingBy(
						VulnerabilityAffectedCpe::getCpeName,
						Collectors.mapping(a -> a.getVulnerability().getId(), Collectors.toList())));

		Set<Long> allVulnIds = affected.stream()
				.map(a -> a.getVulnerability().getId())
				.collect(Collectors.toSet());

		Map<Long, Vulnerability> vulnById = vulnerabilityRepository.findAllById(allVulnIds).stream()
				.collect(Collectors.toMap(Vulnerability::getId, v -> v));

		int pairsFound = 0;
		int alertsInserted = 0;
		int alertsTouched = 0;

		for (SoftwareInstall si : installs) {
			String cpe = si.getCpeName();
			if (cpe == null)
				continue;

			List<Long> vulnIds = cpeToVulnIds.getOrDefault(cpe, List.of());
			for (Long vid : vulnIds) {
				pairsFound++;

				Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vid);
				if (existing.isPresent()) {
					Alert a = existing.get();
					a.touchDetected(now);
					alertRepository.save(a);
					alertsTouched++;
				} else {
					Vulnerability v = vulnById.get(vid);
					if (v == null) continue;
					
					Alert a = new Alert(si, v, now);
					alertRepository.save(a);
					alertsInserted++;
				}
			}
		}

		return new MatchResult(pairsFound, alertsInserted, alertsTouched);
	}

	public record MatchResult(int pairsFound, int alertsInserted, int alertsTouched) {
	}

}
