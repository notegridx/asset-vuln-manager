package dev.notegridx.security.assetvulnmanager.service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertMatchMethod;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
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

		int pairsFound = 0;
		int alertsInserted = 0;
		int alertsTouched = 0;

		// ---- Phase1: canonical/normalized + version range（確度付き）----
		List<SoftwareInstall> installsAll = softwareInstallRepository.findAll();

		for (SoftwareInstall si : installsAll) {
			List<VulnerabilityAffectedCpe> candidates = new ArrayList<>();
			AlertMatchMethod method = null;

			Long vid = si.getCpeVendorId();
			Long pid = si.getCpeProductId();

			// 1) canonical (DICT_ID)
			if (vid != null && pid != null) {
				candidates = affectedCpeRepository.findCandidatesByCanonical(vid, pid);
				if (!candidates.isEmpty()) {
					method = AlertMatchMethod.DICT_ID;
				}
			}

			// 2) fallback: normalized (NORM)
			// affected 側の canonical が未解決(NULL)でも、vendor_norm/product_norm があれば拾えるようにする
			if (candidates.isEmpty()) {
				String vn = normalize(si.getNormalizedVendor());
				String pn = normalize(si.getNormalizedProduct());
				if (vn != null && pn != null) {
					candidates = affectedCpeRepository.findCandidatesByNorm(vn, pn);
					if (!candidates.isEmpty()) {
						method = AlertMatchMethod.NORM;
					}
				}
			}

			if (candidates.isEmpty()) continue;

			String softwareVersion = normalize(si.getVersion());

			// vulnId -> best verdict
			Map<Long, BestVerdict> bestByVuln = new HashMap<>();

			for (VulnerabilityAffectedCpe a : candidates) {
				Long vulnId = a.getVulnerability().getId();

				VersionRangeMatcher.Verdict v = versionMatcher.verdict(
						softwareVersion,
						a.getVersionStartIncluding(),
						a.getVersionStartExcluding(),
						a.getVersionEndIncluding(),
						a.getVersionEndExcluding()
				);

				BestVerdict prev = bestByVuln.get(vulnId);
				BestVerdict next = BestVerdict.from(v);
				if (prev == null || next.isBetterThan(prev)) {
					bestByVuln.put(vulnId, next);
				}
			}

			// NO_MATCH だけ除外
			List<Long> vulnIds = bestByVuln.entrySet().stream()
					.filter(e -> e.getValue().verdict != VersionRangeMatcher.Verdict.NO_MATCH)
					.map(Map.Entry::getKey)
					.distinct()
					.toList();

			if (vulnIds.isEmpty()) continue;

			Map<Long, Vulnerability> vulnById = vulnerabilityRepository.findAllById(vulnIds).stream()
					.collect(java.util.stream.Collectors.toMap(Vulnerability::getId, v -> v));

			for (Long vulnId : vulnIds) {
				pairsFound++;

				BestVerdict bv = bestByVuln.get(vulnId);
				if (bv == null || bv.verdict == VersionRangeMatcher.Verdict.NO_MATCH) continue;

				AlertCertainty certainty = bv.toCertainty();
				AlertUncertainReason reason = bv.toReason();

				Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vulnId);
				if (existing.isPresent()) {
					Alert a = existing.get();
					a.touchDetected(now);
					a.updateMatchContext(certainty, reason, method);
					alertRepository.save(a);
					alertsTouched++;
				} else {
					Vulnerability v = vulnById.get(vulnId);
					if (v == null) continue;

					Alert a = new Alert(si, v, now, certainty, reason, method);
					alertRepository.save(a);
					alertsInserted++;
				}
			}
		}

		// ---- Phase2（既存互換 + 精度UP）: cpe_name 完全一致にも version range を適用（確度付き）----
		List<SoftwareInstall> installsWithCpe = softwareInstallRepository.findByCpeNameIsNotNull();

		// cpe の集合
		List<String> cpes = installsWithCpe.stream()
				.map(SoftwareInstall::getCpeName)
				.filter(Objects::nonNull)
				.distinct()
				.toList();

		if (!cpes.isEmpty()) {
			// cpe -> affected entries（range 含む）
			List<VulnerabilityAffectedCpe> affected = affectedCpeRepository.findByCpeNameIn(cpes);

			Map<String, List<VulnerabilityAffectedCpe>> cpeToAffected = affected.stream()
					.collect(java.util.stream.Collectors.groupingBy(VulnerabilityAffectedCpe::getCpeName));

			for (SoftwareInstall si : installsWithCpe) {
				String cpe = normalize(si.getCpeName());
				if (cpe == null) continue;

				List<VulnerabilityAffectedCpe> list = cpeToAffected.getOrDefault(cpe, List.of());
				if (list.isEmpty()) continue;

				// version は software_installs.version を優先。空なら cpe から補完
				String softwareVersion = normalize(si.getVersion());
				if (softwareVersion == null) {
					softwareVersion = normalize(extractVersionFromCpe23(cpe));
				}

				Map<Long, BestVerdict> bestByVuln = new HashMap<>();
				for (VulnerabilityAffectedCpe a : list) {
					Long vulnId = a.getVulnerability().getId();

					VersionRangeMatcher.Verdict v = versionMatcher.verdict(
							softwareVersion,
							a.getVersionStartIncluding(),
							a.getVersionStartExcluding(),
							a.getVersionEndIncluding(),
							a.getVersionEndExcluding()
					);

					BestVerdict prev = bestByVuln.get(vulnId);
					BestVerdict next = BestVerdict.from(v);
					if (prev == null || next.isBetterThan(prev)) {
						bestByVuln.put(vulnId, next);
					}
				}

				List<Long> vulnIds = bestByVuln.entrySet().stream()
						.filter(e -> e.getValue().verdict != VersionRangeMatcher.Verdict.NO_MATCH)
						.map(Map.Entry::getKey)
						.distinct()
						.toList();

				if (vulnIds.isEmpty()) continue;

				Map<Long, Vulnerability> vulnById = vulnerabilityRepository.findAllById(vulnIds).stream()
						.collect(java.util.stream.Collectors.toMap(Vulnerability::getId, v -> v));

				for (Long vulnId : vulnIds) {
					pairsFound++;

					BestVerdict bv = bestByVuln.get(vulnId);
					if (bv == null || bv.verdict == VersionRangeMatcher.Verdict.NO_MATCH) continue;

					AlertCertainty certainty = bv.toCertainty();
					AlertUncertainReason reason = bv.toReason();

					Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vulnId);
					if (existing.isPresent()) {
						Alert a = existing.get();
						a.touchDetected(now);
						a.updateMatchContext(certainty, reason, AlertMatchMethod.CPE_NAME);
						alertRepository.save(a);
						alertsTouched++;
					} else {
						Vulnerability v = vulnById.get(vulnId);
						if (v == null) continue;

						Alert a = new Alert(si, v, now, certainty, reason, AlertMatchMethod.CPE_NAME);
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

	/**
	 * cpe:2.3:a:vendor:product:version:update:... の "version" を抜く（未知形式には null）
	 */
	private static String extractVersionFromCpe23(String cpe23) {
		if (cpe23 == null) return null;
		String s = cpe23.trim();
		if (s.isEmpty()) return null;

		// 想定: cpe:2.3:a:vendor:product:version:...
		String[] parts = s.split(":");
		if (parts.length < 6) return null;
		if (!"cpe".equalsIgnoreCase(parts[0])) return null;
		if (!"2.3".equalsIgnoreCase(parts[1])) return null;

		String version = parts[5];
		// "*" "-" は「任意/NA」扱い
		if (version == null) return null;
		String v = version.trim();
		if (v.isEmpty()) return null;
		if ("*".equals(v) || "-".equals(v)) return null;
		return v;
	}

	public record MatchResult(int pairsFound, int alertsInserted, int alertsTouched) {}

	/**
	 * Verdict の「強さ」: MATCH > UNKNOWN/UNPARSABLE > NO_MATCH
	 */
	private static final class BestVerdict {
		private static final EnumSet<VersionRangeMatcher.Verdict> UNCONFIRMED =
				EnumSet.of(VersionRangeMatcher.Verdict.UNKNOWN_VERSION, VersionRangeMatcher.Verdict.UNPARSABLE_VERSION);

		private final VersionRangeMatcher.Verdict verdict;

		private BestVerdict(VersionRangeMatcher.Verdict verdict) {
			this.verdict = verdict;
		}

		static BestVerdict from(VersionRangeMatcher.Verdict v) {
			return new BestVerdict(v == null ? VersionRangeMatcher.Verdict.NO_MATCH : v);
		}

		boolean isBetterThan(BestVerdict other) {
			return score(this.verdict) > score(other.verdict);
		}

		private static int score(VersionRangeMatcher.Verdict v) {
			if (v == VersionRangeMatcher.Verdict.MATCH) return 2;
			if (UNCONFIRMED.contains(v)) return 1;
			return 0; // NO_MATCH
		}

		AlertCertainty toCertainty() {
			if (verdict == VersionRangeMatcher.Verdict.MATCH) return AlertCertainty.CONFIRMED;
			if (UNCONFIRMED.contains(verdict)) return AlertCertainty.UNCONFIRMED;
			return AlertCertainty.CONFIRMED; // ここには基本来ない（NO_MATCHは弾く）
		}

		AlertUncertainReason toReason() {
			if (verdict == VersionRangeMatcher.Verdict.UNKNOWN_VERSION) return AlertUncertainReason.MISSING_SOFTWARE_VERSION;
			if (verdict == VersionRangeMatcher.Verdict.UNPARSABLE_VERSION) return AlertUncertainReason.UNPARSABLE_SOFTWARE_VERSION;
			return null;
		}
	}
}