package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
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
import java.util.LinkedHashMap;
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
	private final CriteriaTreeLoader criteriaTreeLoader;
	private final CriteriaEvaluator criteriaEvaluator;
	private final EntityManager entityManager;

	private final VersionRangeMatcher versionMatcher = new VersionRangeMatcher();

	public MatchingService(
			SoftwareInstallRepository softwareInstallRepository,
			VulnerabilityAffectedCpeRepository affectedCpeRepository,
			VulnerabilityRepository vulnerabilityRepository,
			AlertRepository alertRepository,
			CanonicalBackfillService canonicalBackfillService,
			CriteriaTreeLoader criteriaTreeLoader,
			CriteriaEvaluator criteriaEvaluator,
			EntityManager entityManager
	) {
		this.softwareInstallRepository = softwareInstallRepository;
		this.affectedCpeRepository = affectedCpeRepository;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.alertRepository = alertRepository;
		this.canonicalBackfillService = canonicalBackfillService;
		this.criteriaTreeLoader = criteriaTreeLoader;
		this.criteriaEvaluator = criteriaEvaluator;
		this.entityManager = entityManager;
	}

	@Transactional
	public MatchResult matchAndUpsertAlerts() {

		LocalDateTime runStartedAt = DbTime.now();
		LocalDateTime detectedAt = runStartedAt;

		int pairsFound = 0;
		int alertsInserted = 0;
		int alertsTouched = 0;

		List<SoftwareInstall> installsAll = softwareInstallRepository.findAll();

		Map<Long, List<SoftwareInstall>> installsByAssetKey = new LinkedHashMap<>();
		Map<Long, Map<Long, CandidateBundle>> candidateBundlesByAssetKey = new LinkedHashMap<>();
		Map<Long, SoftwareInstall> installById = new HashMap<>();

		for (SoftwareInstall si : installsAll) {
			if (si == null || si.getId() == null) {
				continue;
			}

			long assetKey = assetGroupKey(si);
			installsByAssetKey.computeIfAbsent(assetKey, k -> new ArrayList<>()).add(si);
			candidateBundlesByAssetKey.computeIfAbsent(assetKey, k -> new LinkedHashMap<>());
			installById.put(si.getId(), si);

			collectCandidatesForInstall(
					si,
					candidateBundlesByAssetKey.get(assetKey)
			);
		}

		Map<Long, Vulnerability> vulnerabilityCache = new HashMap<>();
		for (Map<Long, CandidateBundle> perAsset : candidateBundlesByAssetKey.values()) {
			if (perAsset == null || perAsset.isEmpty()) {
				continue;
			}

			List<Long> vulnIds = new ArrayList<>(perAsset.keySet());
			vulnerabilityRepository.findAllById(vulnIds)
					.forEach(v -> vulnerabilityCache.put(v.getId(), v));
		}

		for (Map.Entry<Long, List<SoftwareInstall>> assetEntry : installsByAssetKey.entrySet()) {
			Long assetKey = assetEntry.getKey();
			List<SoftwareInstall> assetInstalls = assetEntry.getValue();

			Map<Long, CandidateBundle> bundles = candidateBundlesByAssetKey.getOrDefault(assetKey, Map.of());
			if (bundles.isEmpty()) {
				continue;
			}

			for (Map.Entry<Long, CandidateBundle> e : bundles.entrySet()) {
				Long vulnId = e.getKey();
				CandidateBundle bundle = e.getValue();
				if (vulnId == null || bundle == null) {
					continue;
				}

				pairsFound++;

				CriteriaTreeLoader.LoadedCriteriaTree tree = criteriaTreeLoader.load(vulnId);

				CriteriaEvaluator.EvalResult result;
				if (tree != null && tree.hasRoots()) {
					result = criteriaEvaluator.evaluate(tree, assetInstalls);
				} else {
					// old ingested data fallback
					result = evaluateFlatFallback(bundle.rows(), assetInstalls, bundle.bestMethod());
				}

				if (result == null || !result.matched() || result.primarySoftwareInstallId() == null) {
					continue;
				}

				SoftwareInstall primaryInstall = installById.get(result.primarySoftwareInstallId());
				if (primaryInstall == null) {
					continue;
				}

				Vulnerability vulnerability = vulnerabilityCache.get(vulnId);
				if (vulnerability == null) {
					continue;
				}

				AlertCertainty certainty = result.certainty();
				AlertUncertainReason reason = result.reason();
				AlertMatchMethod method = result.method() != null ? result.method() : bundle.bestMethod();

				Optional<Alert> existing = alertRepository.findBySoftwareInstallIdAndVulnerabilityId(primaryInstall.getId(), vulnId);
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
					Alert a = new Alert(primaryInstall, vulnerability, detectedAt, certainty, reason, method);
					alertRepository.save(a);
					alertsInserted++;
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

	private void collectCandidatesForInstall(
			SoftwareInstall si,
			Map<Long, CandidateBundle> bundles
	) {
		if (si == null || bundles == null) {
			return;
		}

		Long vid = si.getCpeVendorId();
		Long pid = si.getCpeProductId();

		if (vid != null && pid != null) {
			List<VulnerabilityAffectedCpe> rows = affectedCpeRepository.findCandidatesByCanonical(vid, pid);
			registerCandidateRows(rows, AlertMatchMethod.DICT_ID, bundles);
		}

		String vn = normalize(si.getNormalizedVendor());
		String pn = normalize(si.getNormalizedProduct());
		if (vn != null && pn != null) {
			List<VulnerabilityAffectedCpe> rows = affectedCpeRepository.findCandidatesByNorm(vn, pn);
			registerCandidateRows(rows, AlertMatchMethod.NORM, bundles);
		}

		String cpeName = normalize(si.getCpeName());
		if (cpeName != null) {
			List<VulnerabilityAffectedCpe> rows = affectedCpeRepository.findByCpeName(cpeName);
			registerCandidateRows(rows, AlertMatchMethod.CPE_NAME, bundles);
		}
	}

	private void registerCandidateRows(
			List<VulnerabilityAffectedCpe> rows,
			AlertMatchMethod method,
			Map<Long, CandidateBundle> bundles
	) {
		if (rows == null || rows.isEmpty()) {
			return;
		}

		for (VulnerabilityAffectedCpe row : rows) {
			if (row == null || row.getVulnerability() == null || row.getVulnerability().getId() == null) {
				continue;
			}

			Long vulnId = row.getVulnerability().getId();
			CandidateBundle bundle = bundles.computeIfAbsent(vulnId, k -> new CandidateBundle());
			bundle.addRow(row);
			bundle.promoteMethod(method);
		}
	}

	private CriteriaEvaluator.EvalResult evaluateFlatFallback(
			List<VulnerabilityAffectedCpe> rows,
			List<SoftwareInstall> installs,
			AlertMatchMethod defaultMethod
	) {
		if (rows == null || rows.isEmpty() || installs == null || installs.isEmpty()) {
			return CriteriaEvaluator.EvalResult.noMatch();
		}

		CriteriaEvaluator.EvalResult best = CriteriaEvaluator.EvalResult.noMatch();

		for (SoftwareInstall si : installs) {
			String softwareVersion = normalize(si.getVersion());
			String cpeName = normalize(si.getCpeName());

			if (softwareVersion == null && cpeName != null) {
				softwareVersion = normalize(extractVersionFromCpe23(cpeName));
			}

			for (VulnerabilityAffectedCpe a : rows) {
				if (!isRelevantForAsset(a, si)) {
					continue;
				}

				VersionRangeMatcher.Verdict verdict = versionMatcher.verdict(
						softwareVersion,
						a.getVersionStartIncluding(),
						a.getVersionStartExcluding(),
						a.getVersionEndIncluding(),
						a.getVersionEndExcluding()
				);

				if (verdict == VersionRangeMatcher.Verdict.NO_MATCH) {
					continue;
				}

				BestVerdict bv = BestVerdict.from(verdict);

				CriteriaEvaluator.EvalResult current = CriteriaEvaluator.EvalResult.matched(
						bv.toCertainty(),
						bv.toReason(),
						si.getId(),
						defaultMethod
				);

				best = better(best, current);
			}
		}

		return best;
	}

	private boolean isRelevantForAsset(VulnerabilityAffectedCpe affected, SoftwareInstall install) {
		if (affected == null || install == null) {
			return false;
		}

		String cpePart = normalizePart(affected.getCpePart());
		if (cpePart == null) {
			return false;
		}

		if (!"a".equals(cpePart)) {
			return false;
		}

		String targetSw = normalizeTargetSw(affected.getTargetSw());

		if (targetSw == null || "*".equals(targetSw) || "-".equals(targetSw)) {
			return true;
		}

		if (install.getAsset() == null) {
			return false;
		}

		return switch (detectHostOsFamily(install)) {
			case WINDOWS -> targetSw.equals("windows");
			case MACOS -> targetSw.equals("mac_os") || targetSw.equals("macos");
			case LINUX -> targetSw.equals("linux");
			default -> false;
		};
	}

	private HostOsFamily detectHostOsFamily(SoftwareInstall install) {
		if (install == null || install.getAsset() == null) {
			return HostOsFamily.UNKNOWN;
		}

		String platform = normalize(install.getAsset().getPlatform());
		HostOsFamily byPlatform = mapHostOs(platform);
		if (byPlatform != HostOsFamily.UNKNOWN) {
			return byPlatform;
		}

		String osName = normalize(install.getAsset().getOsName());
		HostOsFamily byOsName = mapHostOs(osName);
		if (byOsName != HostOsFamily.UNKNOWN) {
			return byOsName;
		}

		String osVersion = normalize(install.getAsset().getOsVersion());
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

	private static long assetGroupKey(SoftwareInstall si) {
		if (si != null && si.getAsset() != null && si.getAsset().getId() != null) {
			return si.getAsset().getId();
		}
		return si != null && si.getId() != null ? -si.getId() : Long.MIN_VALUE;
	}

	private static CriteriaEvaluator.EvalResult better(
			CriteriaEvaluator.EvalResult a,
			CriteriaEvaluator.EvalResult b
	) {
		if (score(b) > score(a)) {
			return b;
		}
		if (score(b) < score(a)) {
			return a;
		}

		if (methodScore(b.method()) > methodScore(a.method())) {
			return b;
		}
		if (methodScore(b.method()) < methodScore(a.method())) {
			return a;
		}

		Long aId = a.primarySoftwareInstallId();
		Long bId = b.primarySoftwareInstallId();

		if (aId == null) return b;
		if (bId == null) return a;

		return (bId < aId) ? b : a;
	}

	private static int score(CriteriaEvaluator.EvalResult r) {
		if (r == null || !r.matched()) return 0;
		if (r.certainty() == AlertCertainty.CONFIRMED) return 2;
		return 1;
	}

	private static int methodScore(AlertMatchMethod method) {
		if (method == AlertMatchMethod.DICT_ID) return 3;
		if (method == AlertMatchMethod.NORM) return 2;
		if (method == AlertMatchMethod.CPE_NAME) return 1;
		return 0;
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

	private static final class CandidateBundle {
		private final List<VulnerabilityAffectedCpe> rows = new ArrayList<>();
		private AlertMatchMethod bestMethod;

		void addRow(VulnerabilityAffectedCpe row) {
			if (row != null) {
				rows.add(row);
			}
		}

		void promoteMethod(AlertMatchMethod method) {
			if (method == null) {
				return;
			}
			if (bestMethod == null || methodScore(method) > methodScore(bestMethod)) {
				bestMethod = method;
			}
		}

		List<VulnerabilityAffectedCpe> rows() {
			return rows;
		}

		AlertMatchMethod bestMethod() {
			return bestMethod;
		}
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