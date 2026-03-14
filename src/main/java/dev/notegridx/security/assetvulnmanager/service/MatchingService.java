package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertMatchMethod;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Service
public class MatchingService {

	private final SoftwareInstallRepository softwareInstallRepository;
	private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
	private final VulnerabilityRepository vulnerabilityRepository;
	private final AlertRepository alertRepository;
	private final CanonicalBackfillService canonicalBackfillService;
	private final EntityManager entityManager;

	private final VersionRangeMatcher versionMatcher = new VersionRangeMatcher();

	public MatchingService(
			SoftwareInstallRepository softwareInstallRepository,
			VulnerabilityAffectedCpeRepository affectedCpeRepository,
			VulnerabilityRepository vulnerabilityRepository,
			AlertRepository alertRepository,
			CanonicalBackfillService canonicalBackfillService,
			EntityManager entityManager
	) {
		this.softwareInstallRepository = softwareInstallRepository;
		this.affectedCpeRepository = affectedCpeRepository;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.alertRepository = alertRepository;
		this.canonicalBackfillService = canonicalBackfillService;
		this.entityManager = entityManager;
	}

	@Transactional
	public MatchResult matchAndUpsertAlerts() {

		LocalDateTime runStartedAt = DbTime.now();
		LocalDateTime detectedAt = runStartedAt;

		int pairsFound = 0;
		int alertsInserted = 0;
		int alertsTouched = 0;

		// ---- Phase1: canonical / normalized + version range + OS-aware filter ----
		var installsAll = softwareInstallRepository.findAll();

		for (var si : installsAll) {
			List<VulnerabilityAffectedCpe> candidates = new ArrayList<>();
			AlertMatchMethod method = null;

			Long vid = si.getCpeVendorId();
			Long pid = si.getCpeProductId();

			if (vid != null && pid != null) {
				candidates = affectedCpeRepository.findCandidatesByCanonical(vid, pid);
				if (!candidates.isEmpty()) {
					method = AlertMatchMethod.DICT_ID;
				}
			}

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

			if (candidates.isEmpty()) {
				continue;
			}

			String softwareVersion = normalize(si.getVersion());
			Map<Long, BestVerdict> bestByVuln = new HashMap<>();

			for (VulnerabilityAffectedCpe a : candidates) {
				if (!isRelevantForAsset(a, si.getAsset())) {
					continue;
				}

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

			if (vulnIds.isEmpty()) {
				continue;
			}

			Map<Long, Vulnerability> vulnById = vulnerabilityRepository.findAllById(vulnIds).stream()
					.collect(java.util.stream.Collectors.toMap(Vulnerability::getId, v -> v));

			for (Long vulnId : vulnIds) {
				pairsFound++;

				BestVerdict bv = bestByVuln.get(vulnId);
				if (bv == null || bv.verdict == VersionRangeMatcher.Verdict.NO_MATCH) {
					continue;
				}

				AlertCertainty certainty = bv.toCertainty();
				AlertUncertainReason reason = bv.toReason();

				Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vulnId);
				if (existing.isPresent()) {
					Alert a = existing.get();

					if (a.getStatus() == AlertStatus.CLOSED
							&& a.getCloseReason() == CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED) {
						a.reopen(detectedAt);
					} else {
						a.touchDetected(detectedAt);
					}

					a.updateMatchContext(certainty, reason, method);
					alertRepository.save(a);
					alertsTouched++;
				} else {
					Vulnerability v = vulnById.get(vulnId);
					if (v == null) {
						continue;
					}

					Alert a = new Alert(si, v, detectedAt, certainty, reason, method);
					alertRepository.save(a);
					alertsInserted++;
				}
			}
		}

		// ---- Phase2: cpe_name exact + version range + OS-aware filter ----
		var installsWithCpe = softwareInstallRepository.findByCpeNameIsNotNull();

		List<String> cpes = installsWithCpe.stream()
				.map(s -> normalize(s.getCpeName()))
				.filter(Objects::nonNull)
				.distinct()
				.toList();

		if (!cpes.isEmpty()) {
			List<VulnerabilityAffectedCpe> affected = affectedCpeRepository.findByCpeNameIn(cpes);

			Map<String, List<VulnerabilityAffectedCpe>> cpeToAffected = affected.stream()
					.collect(java.util.stream.Collectors.groupingBy(VulnerabilityAffectedCpe::getCpeName));

			for (var si : installsWithCpe) {
				String cpe = normalize(si.getCpeName());
				if (cpe == null) {
					continue;
				}

				List<VulnerabilityAffectedCpe> list = cpeToAffected.getOrDefault(cpe, List.of());
				if (list.isEmpty()) {
					continue;
				}

				String softwareVersion = normalize(si.getVersion());
				if (softwareVersion == null) {
					softwareVersion = normalize(extractVersionFromCpe23(cpe));
				}

				Map<Long, BestVerdict> bestByVuln = new HashMap<>();

				for (VulnerabilityAffectedCpe a : list) {
					if (!isRelevantForAsset(a, si.getAsset())) {
						continue;
					}

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

				if (vulnIds.isEmpty()) {
					continue;
				}

				Map<Long, Vulnerability> vulnById = vulnerabilityRepository.findAllById(vulnIds).stream()
						.collect(java.util.stream.Collectors.toMap(Vulnerability::getId, v -> v));

				for (Long vulnId : vulnIds) {
					pairsFound++;

					BestVerdict bv = bestByVuln.get(vulnId);
					if (bv == null || bv.verdict == VersionRangeMatcher.Verdict.NO_MATCH) {
						continue;
					}

					AlertCertainty certainty = bv.toCertainty();
					AlertUncertainReason reason = bv.toReason();

					Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(si.getId(), vulnId);
					if (existing.isPresent()) {
						Alert a = existing.get();

						if (a.getStatus() == AlertStatus.CLOSED
								&& a.getCloseReason() == CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED) {
							a.reopen(detectedAt);
						} else {
							a.touchDetected(detectedAt);
						}

						a.updateMatchContext(certainty, reason, AlertMatchMethod.CPE_NAME);
						alertRepository.save(a);
						alertsTouched++;
					} else {
						Vulnerability v = vulnById.get(vulnId);
						if (v == null) {
							continue;
						}

						Alert a = new Alert(si, v, detectedAt, certainty, reason, AlertMatchMethod.CPE_NAME);
						alertRepository.save(a);
						alertsInserted++;
					}
				}
			}
		}

		entityManager.flush();

		int autoClosed = alertRepository.closeStaleOpenAlerts(
				runStartedAt,
				CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED,
				DbTime.now()
		);

		return new MatchResult(pairsFound, alertsInserted, alertsTouched, autoClosed);
	}

	private boolean isRelevantForAsset(VulnerabilityAffectedCpe affected, Asset asset) {
		if (affected == null) {
			return false;
		}

		String cpePart = normalizePart(affected.getCpePart());
		if (cpePart == null) {
			return false;
		}

		// AVM 当面方針: application CPE のみ対象
		if (!"a".equals(cpePart)) {
			return false;
		}

		String targetSw = normalizeTargetSw(affected.getTargetSw());

		// wildcard / omitted は共通ビルド扱い
		if (targetSw == null || "*".equals(targetSw) || "-".equals(targetSw)) {
			return true;
		}

		HostOsFamily host = detectHostOsFamily(asset);
		if (host == HostOsFamily.UNKNOWN) {
			return false;
		}

		return switch (host) {
			case WINDOWS -> targetSw.equals("windows");
			case MACOS -> targetSw.equals("mac_os") || targetSw.equals("macos");
			case LINUX -> targetSw.equals("linux");
			default -> false;
		};
	}

	private HostOsFamily detectHostOsFamily(Asset asset) {
		if (asset == null) {
			return HostOsFamily.UNKNOWN;
		}

		String platform = normalize(asset.getPlatform());
		HostOsFamily byPlatform = mapHostOs(platform);
		if (byPlatform != HostOsFamily.UNKNOWN) {
			return byPlatform;
		}

		String osName = normalize(asset.getOsName());
		HostOsFamily byOsName = mapHostOs(osName);
		if (byOsName != HostOsFamily.UNKNOWN) {
			return byOsName;
		}

		String osVersion = normalize(asset.getOsVersion());
		return mapHostOs(osVersion);
	}

	private HostOsFamily mapHostOs(String raw) {
		String s = normalize(raw);
		if (s == null) {
			return HostOsFamily.UNKNOWN;
		}

		String x = s.toLowerCase();

		if (x.contains("win")) {
			return HostOsFamily.WINDOWS;
		}
		if (x.equals("darwin")
				|| x.contains("mac")
				|| x.contains("os x")
				|| x.contains("osx")) {
			return HostOsFamily.MACOS;
		}
		if (x.contains("linux")
				|| x.contains("ubuntu")
				|| x.contains("debian")
				|| x.contains("rhel")
				|| x.contains("red hat")
				|| x.contains("centos")
				|| x.contains("rocky")
				|| x.contains("alma")
				|| x.contains("suse")
				|| x.contains("fedora")
				|| x.contains("amazon linux")) {
			return HostOsFamily.LINUX;
		}

		return HostOsFamily.UNKNOWN;
	}

	private static String normalizePart(String raw) {
		String s = normalize(raw);
		if (s == null) {
			return null;
		}

		String x = s.toLowerCase();
		return switch (x) {
			case "a", "o", "h" -> x;
			default -> x;
		};
	}

	private static String normalizeTargetSw(String raw) {
		String s = normalize(raw);
		if (s == null) {
			return null;
		}

		String x = s.toLowerCase();

		return switch (x) {
			case "windows", "microsoft_windows" -> "windows";
			case "mac_os", "macos", "mac_os_x", "darwin" -> "mac_os";
			case "linux", "gnu_linux" -> "linux";
			case "iphone_os", "ios", "ipad_os", "android" -> x;
			case "*", "-" -> x;
			default -> x;
		};
	}

	private static String normalize(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}

	/**
	 * cpe:2.3:a:vendor:product:version:update:... の version を抜く。
	 */
	private static String extractVersionFromCpe23(String cpe23) {
		if (cpe23 == null) return null;

		String s = cpe23.trim();
		if (s.isEmpty()) return null;

		String[] parts = s.split(":", -1);
		if (parts.length < 6) return null;
		if (!"cpe".equalsIgnoreCase(parts[0])) return null;
		if (!"2.3".equalsIgnoreCase(parts[1])) return null;

		String version = parts[5];
		if (version == null) return null;

		String v = version.trim();
		if (v.isEmpty() || "*".equals(v) || "-".equals(v)) {
			return null;
		}

		return v;
	}

	public record MatchResult(int pairsFound, int alertsInserted, int alertsTouched, int alertsAutoClosed) {
	}

	private enum HostOsFamily {
		WINDOWS,
		MACOS,
		LINUX,
		UNKNOWN
	}

	private static final class BestVerdict {
		private static final EnumSet<VersionRangeMatcher.Verdict> UNCONFIRMED =
				EnumSet.of(
						VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT,
						VersionRangeMatcher.Verdict.UNKNOWN_VERSION,
						VersionRangeMatcher.Verdict.UNPARSABLE_VERSION
				);

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
			return 0;
		}

		AlertCertainty toCertainty() {
			if (verdict == VersionRangeMatcher.Verdict.MATCH) return AlertCertainty.CONFIRMED;
			if (UNCONFIRMED.contains(verdict)) return AlertCertainty.UNCONFIRMED;
			return AlertCertainty.CONFIRMED;
		}

		AlertUncertainReason toReason() {
			if (verdict == VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT) return AlertUncertainReason.NO_VERSION_CONSTRAINT;
			if (verdict == VersionRangeMatcher.Verdict.UNKNOWN_VERSION) return AlertUncertainReason.MISSING_SOFTWARE_VERSION;
			if (verdict == VersionRangeMatcher.Verdict.UNPARSABLE_VERSION) return AlertUncertainReason.UNPARSABLE_SOFTWARE_VERSION;
			return null;
		}
	}
}