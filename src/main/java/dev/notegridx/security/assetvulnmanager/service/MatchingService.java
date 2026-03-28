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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Service
public class MatchingService {

	private static final Logger log = LoggerFactory.getLogger(MatchingService.class);
	private static final int WRITE_FLUSH_INTERVAL = 200;

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

		long startedAtNs = System.nanoTime();

		LocalDateTime runStartedAt = DbTime.now();
		LocalDateTime detectedAt = runStartedAt;

		int pairsFound = 0;
		int alertsInserted = 0;
		int alertsTouched = 0;

		List<SoftwareInstall> installsAll = softwareInstallRepository.findAllWithAsset();

		Map<Long, List<SoftwareInstall>> installsByAssetKey = new LinkedHashMap<>();
		Map<Long, AssetInstallIndex> installIndexByAssetKey = new LinkedHashMap<>();
		Map<Long, Map<Long, CandidateBundle>> candidateBundlesByAssetKey = new LinkedHashMap<>();
		Map<Long, SoftwareInstall> installById = new HashMap<>();

		Set<String> canonicalPairs = new LinkedHashSet<>();
		Set<String> normPairs = new LinkedHashSet<>();
		Set<String> cpeNames = new LinkedHashSet<>();

		for (SoftwareInstall si : installsAll) {
			if (si == null || si.getId() == null) {
				continue;
			}
			if (si.isCanonicalLinkDisabled()) {
				continue;
			}

			long assetKey = assetGroupKey(si);
			installsByAssetKey.computeIfAbsent(assetKey, k -> new ArrayList<>()).add(si);
			candidateBundlesByAssetKey.computeIfAbsent(assetKey, k -> new LinkedHashMap<>());
			installById.put(si.getId(), si);

			Long vendorId = si.getCpeVendorId();
			Long productId = si.getCpeProductId();
			if (vendorId != null && productId != null) {
				canonicalPairs.add(canonicalKey(vendorId, productId));
			}

			String vendorNorm = normalize(si.getNormalizedVendor());
			String productNorm = normalize(si.getNormalizedProduct());
			if (vendorNorm != null && productNorm != null) {
				normPairs.add(normKey(vendorNorm, productNorm));
			}

			String cpeName = normalize(si.getCpeName());
			if (cpeName != null) {
				cpeNames.add(cpeName);
			}
		}

		for (Map.Entry<Long, List<SoftwareInstall>> e : installsByAssetKey.entrySet()) {
			installIndexByAssetKey.put(e.getKey(), AssetInstallIndex.from(e.getValue()));
		}

		Map<String, List<VulnerabilityAffectedCpe>> canonicalCandidateMap = preloadCanonicalCandidates(canonicalPairs);
		Map<String, List<VulnerabilityAffectedCpe>> normCandidateMap = preloadNormCandidates(normPairs);
		Map<String, List<VulnerabilityAffectedCpe>> cpeNameCandidateMap = preloadCpeNameCandidates(cpeNames);

		for (SoftwareInstall si : installsAll) {
			if (si == null || si.getId() == null) {
				continue;
			}
			if (si.isCanonicalLinkDisabled()) {
				continue;
			}

			long assetKey = assetGroupKey(si);
			Map<Long, CandidateBundle> bundles = candidateBundlesByAssetKey.get(assetKey);
			collectCandidatesForInstallFromPreloadedMaps(
					si,
					bundles,
					canonicalCandidateMap,
					normCandidateMap,
					cpeNameCandidateMap
			);
		}

		Set<Long> candidateVulnIdSet = new LinkedHashSet<>();
		for (Map<Long, CandidateBundle> perAsset : candidateBundlesByAssetKey.values()) {
			if (perAsset == null || perAsset.isEmpty()) {
				continue;
			}
			candidateVulnIdSet.addAll(perAsset.keySet());
		}

		Map<Long, Vulnerability> vulnerabilityCache = new HashMap<>();
		if (!candidateVulnIdSet.isEmpty()) {
			vulnerabilityRepository.findAllById(candidateVulnIdSet)
					.forEach(v -> vulnerabilityCache.put(v.getId(), v));
		}

		List<Long> candidateVulnIds = new ArrayList<>(candidateVulnIdSet);

		Map<String, Alert> existingAlertMap = new HashMap<>();
		List<Long> installIds = installsAll.stream()
				.filter(Objects::nonNull)
				.filter(si -> !si.isCanonicalLinkDisabled())
				.map(SoftwareInstall::getId)
				.filter(Objects::nonNull)
				.toList();

		if (!installIds.isEmpty() && !candidateVulnIds.isEmpty()) {
			for (Alert alert : alertRepository.findBySoftwareInstallIdInAndVulnerabilityIdIn(installIds, candidateVulnIds)) {
				if (alert == null
						|| alert.getSoftwareInstall() == null
						|| alert.getSoftwareInstall().getId() == null
						|| alert.getVulnerability() == null
						|| alert.getVulnerability().getId() == null) {
					continue;
				}
				existingAlertMap.put(
						alertKey(alert.getSoftwareInstall().getId(), alert.getVulnerability().getId()),
						alert
				);
			}
		}

		Map<Long, CriteriaTreeLoader.LoadedCriteriaTree> criteriaTreeCache = new HashMap<>();
		List<Alert> pendingSaves = new ArrayList<>(WRITE_FLUSH_INTERVAL);

		for (Map.Entry<Long, List<SoftwareInstall>> assetEntry : installsByAssetKey.entrySet()) {
			Long assetKey = assetEntry.getKey();
			List<SoftwareInstall> assetInstalls = assetEntry.getValue();
			AssetInstallIndex assetInstallIndex =
					installIndexByAssetKey.getOrDefault(assetKey, AssetInstallIndex.empty());

			if (assetInstalls == null || assetInstalls.isEmpty()) {
				continue;
			}

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

				CriteriaTreeLoader.LoadedCriteriaTree tree =
						criteriaTreeCache.computeIfAbsent(vulnId, criteriaTreeLoader::load);

				CriteriaEvaluator.EvalResult result;
				if (tree != null && tree.hasRoots()) {
					result = criteriaEvaluator.evaluate(tree, assetInstallIndex);
				} else {
					result = evaluateFlatFallback(
							vulnerabilityCache.get(vulnId),
							bundle.rows(),
							assetInstalls,
							bundle.bestMethod()
					);
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

				String key = alertKey(primaryInstall.getId(), vulnId);
				Alert existing = existingAlertMap.get(key);

				if (existing != null) {
					Alert a = existing;

					if (a.getStatus() == AlertStatus.CLOSED
							&& a.getCloseReason() == CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED) {
						a.reopen(detectedAt);
					} else {
						a.touchDetected(detectedAt);
					}

					a.updateMatchContext(certainty, reason, method);
					pendingSaves.add(a);
					alertsTouched++;
				} else {
					Alert a = new Alert(primaryInstall, vulnerability, detectedAt, certainty, reason, method);
					pendingSaves.add(a);
					existingAlertMap.put(key, a);
					alertsInserted++;
				}

				flushPendingAlertsIfNeeded(pendingSaves, existingAlertMap);
			}
		}

		flushPendingAlerts(pendingSaves, existingAlertMap);
		entityManager.flush();

		int autoClosed = alertRepository.closeStaleOpenAlerts(
				runStartedAt,
				CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED,
				DbTime.now()
		);

		long elapsedMs = (System.nanoTime() - startedAtNs) / 1_000_000;
		log.info(
				"Generate Alerts finished in {} ms (pairsFound={}, alertsInserted={}, alertsTouched={}, alertsAutoClosed={})",
				elapsedMs,
				pairsFound,
				alertsInserted,
				alertsTouched,
				autoClosed
		);

		return new MatchResult(pairsFound, alertsInserted, alertsTouched, autoClosed);
	}

	private static String alertKey(Long softwareInstallId, Long vulnerabilityId) {
		return softwareInstallId + ":" + vulnerabilityId;
	}

	private void collectCandidatesForInstallFromPreloadedMaps(
			SoftwareInstall si,
			Map<Long, CandidateBundle> bundles,
			Map<String, List<VulnerabilityAffectedCpe>> canonicalCandidateMap,
			Map<String, List<VulnerabilityAffectedCpe>> normCandidateMap,
			Map<String, List<VulnerabilityAffectedCpe>> cpeNameCandidateMap
	) {
		if (si == null || bundles == null) {
			return;
		}

		Long vid = si.getCpeVendorId();
		Long pid = si.getCpeProductId();
		if (vid != null && pid != null) {
			registerCandidateRows(
					canonicalCandidateMap.getOrDefault(canonicalKey(vid, pid), List.of()),
					AlertMatchMethod.DICT_ID,
					bundles
			);
		}

		String vn = normalize(si.getNormalizedVendor());
		String pn = normalize(si.getNormalizedProduct());
		if (vn != null && pn != null) {
			registerCandidateRows(
					normCandidateMap.getOrDefault(normKey(vn, pn), List.of()),
					AlertMatchMethod.NORM,
					bundles
			);
		}

		String cpeName = normalize(si.getCpeName());
		if (cpeName != null) {
			registerCandidateRows(
					cpeNameCandidateMap.getOrDefault(cpeName, List.of()),
					AlertMatchMethod.CPE_NAME,
					bundles
			);
		}
	}

	private Map<String, List<VulnerabilityAffectedCpe>> preloadCanonicalCandidates(Set<String> canonicalPairs) {
		Map<String, List<VulnerabilityAffectedCpe>> out = new HashMap<>();
		if (canonicalPairs == null || canonicalPairs.isEmpty()) {
			return out;
		}

		List<VulnerabilityAffectedCpeRepository.CanonicalPair> queryPairs = new ArrayList<>();
		for (String pairKey : canonicalPairs) {
			if (pairKey == null || pairKey.isBlank()) {
				continue;
			}

			int sep = pairKey.indexOf(':');
			if (sep <= 0 || sep >= pairKey.length() - 1) {
				continue;
			}

			try {
				Long vendorId = Long.parseLong(pairKey.substring(0, sep));
				Long productId = Long.parseLong(pairKey.substring(sep + 1));
				queryPairs.add(new VulnerabilityAffectedCpeRepository.CanonicalPair(vendorId, productId));
			} catch (NumberFormatException ignore) {
				// ignore malformed pair
			}
		}

		if (queryPairs.isEmpty()) {
			return out;
		}

		List<VulnerabilityAffectedCpe> rows = affectedCpeRepository.findAllByCanonicalPairs(queryPairs);
		for (VulnerabilityAffectedCpe row : rows) {
			if (row == null || row.getCpeVendorId() == null || row.getCpeProductId() == null) {
				continue;
			}
			out.computeIfAbsent(canonicalKey(row.getCpeVendorId(), row.getCpeProductId()), k -> new ArrayList<>())
					.add(row);
		}
		return out;
	}

	private Map<String, List<VulnerabilityAffectedCpe>> preloadNormCandidates(Set<String> normPairs) {
		Map<String, List<VulnerabilityAffectedCpe>> out = new HashMap<>();
		if (normPairs == null || normPairs.isEmpty()) {
			return out;
		}

		List<VulnerabilityAffectedCpeRepository.NormPair> queryPairs = new ArrayList<>();
		for (String pairKey : normPairs) {
			if (pairKey == null || pairKey.isBlank()) {
				continue;
			}

			int sep = pairKey.indexOf(':');
			if (sep <= 0 || sep >= pairKey.length() - 1) {
				continue;
			}

			String vendorNorm = normalize(pairKey.substring(0, sep));
			String productNorm = normalize(pairKey.substring(sep + 1));
			if (vendorNorm == null || productNorm == null) {
				continue;
			}

			queryPairs.add(new VulnerabilityAffectedCpeRepository.NormPair(vendorNorm, productNorm));
		}

		if (queryPairs.isEmpty()) {
			return out;
		}

		List<VulnerabilityAffectedCpe> rows = affectedCpeRepository.findAllByNormPairs(queryPairs);
		for (VulnerabilityAffectedCpe row : rows) {
			if (row == null) {
				continue;
			}
			String vendorNorm = normalize(row.getVendorNorm());
			String productNorm = normalize(row.getProductNorm());
			if (vendorNorm == null || productNorm == null) {
				continue;
			}
			out.computeIfAbsent(normKey(vendorNorm, productNorm), k -> new ArrayList<>())
					.add(row);
		}
		return out;
	}

	private Map<String, List<VulnerabilityAffectedCpe>> preloadCpeNameCandidates(Set<String> cpeNames) {
		Map<String, List<VulnerabilityAffectedCpe>> out = new HashMap<>();
		if (cpeNames == null || cpeNames.isEmpty()) {
			return out;
		}

		List<VulnerabilityAffectedCpe> rows =
				affectedCpeRepository.findByCpeNameIn(new ArrayList<>(cpeNames));
		for (VulnerabilityAffectedCpe row : rows) {
			if (row == null) {
				continue;
			}
			String cpeName = normalize(row.getCpeName());
			if (cpeName == null) {
				continue;
			}
			out.computeIfAbsent(cpeName, k -> new ArrayList<>())
					.add(row);
		}
		return out;
	}

	private static String canonicalKey(Long vendorId, Long productId) {
		return vendorId + ":" + productId;
	}

	private static String normKey(String vendorNorm, String productNorm) {
		return vendorNorm + ":" + productNorm;
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
			Vulnerability vulnerability,
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

				VersionRangeMatcher.Verdict verdict = evaluateAffectedVersionVerdict(a, softwareVersion);

				if (verdict == VersionRangeMatcher.Verdict.NO_MATCH) {
					logVersionEvaluation(
							si,
							vulnerability,
							a,
							defaultMethod,
							softwareVersion,
							verdict,
							null,
							null
					);
					continue;
				}

				BestVerdict bv = BestVerdict.from(verdict);
				AlertCertainty certainty = bv.toCertainty();
				AlertUncertainReason reason = bv.toReason();

				logVersionEvaluation(
						si,
						vulnerability,
						a,
						defaultMethod,
						softwareVersion,
						verdict,
						certainty,
						reason
				);

				CriteriaEvaluator.EvalResult current = CriteriaEvaluator.EvalResult.matched(
						certainty,
						reason,
						si.getId(),
						defaultMethod
				);

				best = better(best, current);
			}
		}

		return best;
	}

	private VersionRangeMatcher.Verdict evaluateAffectedVersionVerdict(
			VulnerabilityAffectedCpe affected,
			String softwareVersion
	) {
		if (affected == null) {
			return VersionRangeMatcher.Verdict.NO_MATCH;
		}

		boolean hasRange =
				normalize(affected.getVersionStartIncluding()) != null
						|| normalize(affected.getVersionStartExcluding()) != null
						|| normalize(affected.getVersionEndIncluding()) != null
						|| normalize(affected.getVersionEndExcluding()) != null;

		if (hasRange) {
			return versionMatcher.verdict(
					softwareVersion,
					affected.getVersionStartIncluding(),
					affected.getVersionStartExcluding(),
					affected.getVersionEndIncluding(),
					affected.getVersionEndExcluding()
			);
		}

		String affectedVersion = normalize(extractVersionFromCpe23(affected.getCpeName()));
		if (affectedVersion == null) {
			return VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT;
		}

		if (softwareVersion == null) {
			return VersionRangeMatcher.Verdict.UNKNOWN_VERSION;
		}

		try {
			return versionMatcher.compare(softwareVersion, affectedVersion) == 0
					? VersionRangeMatcher.Verdict.MATCH
					: VersionRangeMatcher.Verdict.NO_MATCH;
		} catch (Exception e) {
			return VersionRangeMatcher.Verdict.UNPARSABLE_VERSION;
		}
	}

	private void logVersionEvaluation(
			SoftwareInstall sw,
			Vulnerability vuln,
			VulnerabilityAffectedCpe cpe,
			AlertMatchMethod matchedBy,
			String softwareVersion,
			VersionRangeMatcher.Verdict verdict,
			AlertCertainty certainty,
			AlertUncertainReason uncertainReason
	) {
		if (!log.isDebugEnabled()) {
			return;
		}

		log.debug(
				"version-eval swId={} assetId={} vulnId={} cve={} matchedBy={} " +
						"swVersion='{}' cpe='{}' startInc='{}' startExc='{}' endInc='{}' endExc='{}' " +
						"criteriaNodeId={} rootGroupNo={} verdict={} certainty={} uncertainReason={}",
				sw != null ? sw.getId() : null,
				(sw != null && sw.getAsset() != null) ? sw.getAsset().getId() : null,
				vuln != null ? vuln.getId() : null,
				vuln != null ? vuln.getExternalId() : null,
				matchedBy,
				softwareVersion,
				cpe != null ? cpe.getCpeName() : null,
				cpe != null ? cpe.getVersionStartIncluding() : null,
				cpe != null ? cpe.getVersionStartExcluding() : null,
				cpe != null ? cpe.getVersionEndIncluding() : null,
				cpe != null ? cpe.getVersionEndExcluding() : null,
				cpe != null ? cpe.getCriteriaNodeId() : null,
				cpe != null ? cpe.getRootGroupNo() : null,
				verdict,
				certainty,
				uncertainReason
		);
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

	private void flushPendingAlerts(
			List<Alert> pendingSaves,
			Map<String, Alert> existingAlertMap
	) {
		if (pendingSaves == null || pendingSaves.isEmpty()) {
			return;
		}

		List<Alert> saved = alertRepository.saveAll(pendingSaves);
		entityManager.flush();
		entityManager.clear();

		for (Alert alert : saved) {
			if (alert == null
					|| alert.getSoftwareInstall() == null
					|| alert.getSoftwareInstall().getId() == null
					|| alert.getVulnerability() == null
					|| alert.getVulnerability().getId() == null) {
				continue;
			}

			existingAlertMap.put(
					alertKey(alert.getSoftwareInstall().getId(), alert.getVulnerability().getId()),
					alert
			);
		}

		pendingSaves.clear();
	}

	private void flushPendingAlertsIfNeeded(
			List<Alert> pendingSaves,
			Map<String, Alert> existingAlertMap
	) {
		if (pendingSaves == null || pendingSaves.isEmpty()) {
			return;
		}
		if (pendingSaves.size() >= WRITE_FLUSH_INTERVAL) {
			flushPendingAlerts(pendingSaves, existingAlertMap);
		}
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