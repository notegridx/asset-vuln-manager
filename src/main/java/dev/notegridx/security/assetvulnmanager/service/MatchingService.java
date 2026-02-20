package dev.notegridx.security.assetvulnmanager.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
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

	private final VersionRangeMatcher versionMatcher = new VersionRangeMatcher();

	public MatchingService(
			SoftwareInstallRepository softwareInstallRepository,
			VulnerabilityAffectedCpeRepository affectedCpeRepository,
			VulnerabilityRepository vulnerabilityRepository,
			AlertRepository alertRepository
	) {
		this.softwareInstallRepository = softwareInstallRepository;
		this.affectedCpeRepository = affectedCpeRepository;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.alertRepository = alertRepository;
	}

	@Transactional
	public MatchResult matchAndUpsertAlerts() {
		LocalDateTime now = LocalDateTime.now();

		// ---- Phase2用（既存互換）：cpe_nameが入っているものは一括で拾う ----
		List<SoftwareInstall> installsWithCpe = softwareInstallRepository.findByCpeNameIsNotNull();
		List<String> cpes = installsWithCpe.stream()
				.map(SoftwareInstall::getCpeName)
				.filter(Objects::nonNull)
				.distinct()
				.toList();

		Map<String, List<Long>> cpeToVulnIds;
		Set<Long> allVulnIdsPhase2;

		if (!cpes.isEmpty()) {
			List<VulnerabilityAffectedCpe> affected = affectedCpeRepository.findByCpeNameIn(cpes);

			cpeToVulnIds = affected.stream()
					.collect(Collectors.groupingBy(
							VulnerabilityAffectedCpe::getCpeName,
							Collectors.mapping(a -> a.getVulnerability().getId(), Collectors.toList())
					));

			allVulnIdsPhase2 = affected.stream()
					.map(a -> a.getVulnerability().getId())
					.collect(Collectors.toSet());
		} else {
			cpeToVulnIds = Map.of();
			allVulnIdsPhase2 = Set.of();
		}

		// ---- Phase1用：全ソフト（canonical/normalized で候補抽出）----
		List<SoftwareInstall> installsAll = softwareInstallRepository.findAll();

		// vulnのロード（Phase1/2で出てくるIDを最終的にまとめて引くため、一旦集める）
		// Phase1は候補抽出が installごとになるので、ここでは後段で都度ロードする方針でもよいが、
		// とりあえず Alert作成時に必要な Vulnerability を都度 findAllById でまとめるために収集する。
		// → 実装簡素化のため、ここでは “必要になったら都度ロード” 方式を採用する。

		int pairsFound = 0;
		int alertsInserted = 0;
		int alertsTouched = 0;

		// ---- Phase1: canonical/normalized + version range ----
		for (SoftwareInstall si : installsAll) {
			List<VulnerabilityAffectedCpe> candidates = new ArrayList<>();

			Long vid = si.getCpeVendorId();
			Long pid = si.getCpeProductId();

			if (vid != null && pid != null) {
				candidates = affectedCpeRepository.findCandidatesByCanonical(vid, pid);
			} else {
				String vn = normalize(si.getNormalizedVendor());
				String pn = normalize(si.getNormalizedProduct());
				if (vn != null && pn != null) {
					candidates = affectedCpeRepository.findCandidatesByNorm(vn, pn);
				}
			}

			if (candidates.isEmpty()) continue;

			String version = normalize(si.getVersion());

			// candidates → version range で絞る → vulnerabilityId の集合へ
			List<Long> vulnIds = candidates.stream()
					.filter(a -> versionMatcher.matches(
							version,
							a.getVersionStartIncluding(),
							a.getVersionStartExcluding(),
							a.getVersionEndIncluding(),
							a.getVersionEndExcluding()
					))
					.map(a -> a.getVulnerability().getId())
					.distinct()
					.toList();

			if (vulnIds.isEmpty()) continue;

			Map<Long, Vulnerability> vulnById = vulnerabilityRepository.findAllById(vulnIds).stream()
					.collect(Collectors.toMap(Vulnerability::getId, v -> v));

			for (Long vulnId : vulnIds) {
				pairsFound++;

				Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vulnId);
				if (existing.isPresent()) {
					Alert a = existing.get();
					a.touchDetected(now);
					alertRepository.save(a);
					alertsTouched++;
				} else {
					Vulnerability v = vulnById.get(vulnId);
					if (v == null) continue;

					Alert a = new Alert(si, v, now);
					alertRepository.save(a);
					alertsInserted++;
				}
			}
		}

		// ---- Phase2: 既存互換 cpe_name 完全一致（version rangeは扱わない：従来通り）----
		// ※ Phase1で拾えている可能性があるので、uq_alert_pair が最終的に重複を抑止する
		if (!cpes.isEmpty()) {
			Map<Long, Vulnerability> vulnByIdPhase2 =
					vulnerabilityRepository.findAllById(allVulnIdsPhase2).stream()
							.collect(Collectors.toMap(Vulnerability::getId, v -> v));

			for (SoftwareInstall si : installsWithCpe) {
				String cpe = si.getCpeName();
				if (cpe == null) continue;

				List<Long> vulnIds = cpeToVulnIds.getOrDefault(cpe, List.of());
				for (Long vulnId : vulnIds) {
					pairsFound++;

					Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vulnId);
					if (existing.isPresent()) {
						Alert a = existing.get();
						a.touchDetected(now);
						alertRepository.save(a);
						alertsTouched++;
					} else {
						Vulnerability v = vulnByIdPhase2.get(vulnId);
						if (v == null) continue;

						Alert a = new Alert(si, v, now);
						alertRepository.save(a);
						alertsInserted++;
					}
				}
			}
		}

		return new MatchResult(pairsFound, alertsInserted, alertsTouched);
	}

	private static String normalize(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}

	public record MatchResult(int pairsFound, int alertsInserted, int alertsTouched) {}
}