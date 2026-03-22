package dev.notegridx.security.assetvulnmanager.service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaCpe;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityCriteriaNode;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaNodeType;
import dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaOperator;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeNameParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdClient;
import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityCriteriaNodeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;

@Service
public class NvdImportService {

	private static final Logger log = LoggerFactory.getLogger(NvdImportService.class);

	private static final String SOURCE_NVD = "NVD";

	private final NvdClient nvdClient;
	private final VulnerabilityRepository vulnerabilityRepository;
	private final VulnerabilityAffectedCpeRepository affectedCpeRepository;
	private final VulnerabilityCriteriaNodeRepository criteriaNodeRepository;
	private final VulnerabilityCriteriaCpeRepository criteriaCpeRepository;

	private final CpeNameParser cpeNameParser;
	private final VendorProductNormalizer normalizer;
	private final CpeVendorRepository cpeVendorRepository;
	private final CpeProductRepository cpeProductRepository;

	public NvdImportService(
			NvdClient nvdClient,
			VulnerabilityRepository vulnerabilityRepository,
			VulnerabilityAffectedCpeRepository affectedCpeRepository,
			VulnerabilityCriteriaNodeRepository criteriaNodeRepository,
			VulnerabilityCriteriaCpeRepository criteriaCpeRepository,
			CpeNameParser cpeNameParser,
			VendorProductNormalizer normalizer,
			CpeVendorRepository cpeVendorRepository,
			CpeProductRepository cpeProductRepository
	) {
		this.nvdClient = nvdClient;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.affectedCpeRepository = affectedCpeRepository;
		this.criteriaNodeRepository = criteriaNodeRepository;
		this.criteriaCpeRepository = criteriaCpeRepository;
		this.cpeNameParser = cpeNameParser;
		this.normalizer = normalizer;
		this.cpeVendorRepository = cpeVendorRepository;
		this.cpeProductRepository = cpeProductRepository;
	}

	@Transactional
	public ImportResult importFromNvd(OffsetDateTime lastModStart, OffsetDateTime lastModEnd, int maxResults) {

		int safeMax = Math.max(1, Math.min(maxResults, 2000));
		log.info("NVD import start: range={}..{}, maxResults={}", lastModStart, lastModEnd, safeMax);

		List<NvdCveResponse.VulnerabilityItem> items =
				nvdClient.fetchByLastModifiedRange(lastModStart, lastModEnd, safeMax);

		int vulnUpserted = 0;
		int affectedInserted = 0;

		for (NvdCveResponse.VulnerabilityItem item : items) {
			if (item == null || item.cve() == null) continue;

			String cveId = normalize(item.cve().id());
			if (cveId == null) continue;

			Vulnerability v = vulnerabilityRepository.findBySourceAndExternalId(SOURCE_NVD, cveId)
					.orElseGet(() -> new Vulnerability(SOURCE_NVD, cveId));

			String desc = pickEnDescription(item.cve().descriptions());

			CvssPick cvss = pickCvss(item.cve().metrics());
			LocalDateTime publishedAt = parseNvdDateTime(item.cve().published());
			LocalDateTime lastModifiedAt = parseNvdDateTime(item.cve().lastModified());

			v.applyNvdDetails(
					desc,
					cvss.version(),
					cvss.score(),
					publishedAt,
					lastModifiedAt
			);

			v = vulnerabilityRepository.save(v);
			vulnUpserted++;

			CriteriaParseBundle bundle = buildCriteriaParseBundle(item.cve().configurations());

			replaceCriteriaTree(v, bundle.roots());

			for (AffectedSpec spec : bundle.affected()) {

				String vsi = nullToEmpty(spec.versionStartIncluding());
				String vse = nullToEmpty(spec.versionStartExcluding());
				String vei = nullToEmpty(spec.versionEndIncluding());
				String vee = nullToEmpty(spec.versionEndExcluding());

				Long vulnId = v.getId();
				if (vulnId != null) {
					boolean exists = affectedCpeRepository
							.existsByVulnerabilityIdAndCpeNameAndVersionStartIncludingAndVersionStartExcludingAndVersionEndIncludingAndVersionEndExcluding(
									vulnId,
									spec.criteria(),
									vsi, vse, vei, vee
							);
					if (exists) {
						continue;
					}
				}

				affectedCpeRepository.save(new VulnerabilityAffectedCpe(
						v,
						spec.criteria(),
						spec.vendorId(),
						spec.productId(),
						spec.vendorNorm(),
						spec.productNorm(),
						spec.cpePart(),
						spec.targetSw(),
						spec.targetHw(),
						vsi, vse, vei, vee,
						null,
						0
				));
				affectedInserted++;
			}
		}

		log.info("NVD import done: vulnerabilitiesUpserted={}, affectedCpesInserted={}, fetched={}",
				vulnUpserted, affectedInserted, items.size());

		return new ImportResult(vulnUpserted, affectedInserted, items.size());
	}

	private void replaceCriteriaTree(Vulnerability vulnerability, List<ParsedCriteriaRoot> roots) {
		if (vulnerability == null || vulnerability.getId() == null) {
			return;
		}

		criteriaCpeRepository.deleteByVulnerabilityId(vulnerability.getId());
		criteriaNodeRepository.deleteByVulnerabilityId(vulnerability.getId());

		if (roots == null || roots.isEmpty()) {
			return;
		}

		int rootSort = 0;
		for (ParsedCriteriaRoot root : roots) {
			if (root == null || root.rootNode() == null) continue;
			persistCriteriaNodeRecursive(
					vulnerability,
					null,
					root.rootGroupNo(),
					rootSort++,
					root.rootNode()
			);
		}
	}

	private void persistCriteriaNodeRecursive(
			Vulnerability vulnerability,
			Long parentId,
			int rootGroupNo,
			int sortOrder,
			ParsedCriteriaNode parsed
	) {
		if (parsed == null) return;

		VulnerabilityCriteriaNode savedNode = criteriaNodeRepository.save(
				new VulnerabilityCriteriaNode(
						vulnerability,
						parentId,
						rootGroupNo,
						parsed.nodeType(),
						parsed.operator(),
						parsed.negate(),
						sortOrder
				)
		);

		if (parsed.nodeType() == CriteriaNodeType.LEAF_GROUP && parsed.cpes() != null) {
			for (ParsedCriteriaCpe cpe : parsed.cpes()) {
				if (cpe == null) continue;

				criteriaCpeRepository.save(new VulnerabilityCriteriaCpe(
						savedNode.getId(),
						vulnerability,
						cpe.cpeName(),
						cpe.cpeVendorId(),
						cpe.cpeProductId(),
						cpe.vendorNorm(),
						cpe.productNorm(),
						cpe.cpePart(),
						cpe.targetSw(),
						cpe.targetHw(),
						cpe.versionStartIncluding(),
						cpe.versionStartExcluding(),
						cpe.versionEndIncluding(),
						cpe.versionEndExcluding(),
						cpe.matchVulnerable()
				));
			}
		}

		if (parsed.children() != null && !parsed.children().isEmpty()) {
			int childSort = 0;
			for (ParsedCriteriaNode child : parsed.children()) {
				persistCriteriaNodeRecursive(
						vulnerability,
						savedNode.getId(),
						rootGroupNo,
						childSort++,
						child
				);
			}
		}
	}

	private CriteriaParseBundle buildCriteriaParseBundle(List<NvdCveResponse.Configurations> configurationsList) {
		Set<AffectedSpec> affected = new LinkedHashSet<>();
		List<ParsedCriteriaRoot> roots = new ArrayList<>();

		if (configurationsList == null || configurationsList.isEmpty()) {
			return new CriteriaParseBundle(new ArrayList<>(affected), roots);
		}

		int rootGroupNo = 0;
		for (NvdCveResponse.Configurations configurations : configurationsList) {
			if (configurations == null || configurations.nodes() == null || configurations.nodes().isEmpty()) {
				rootGroupNo++;
				continue;
			}

			List<ParsedCriteriaNode> topNodes = new ArrayList<>();
			for (NvdCveResponse.Node node : configurations.nodes()) {
				ParsedCriteriaNode parsed = toParsedCriteriaNode(node, affected);
				if (parsed != null) {
					topNodes.add(parsed);
				}
			}

			if (topNodes.isEmpty()) {
				rootGroupNo++;
				continue;
			}

			ParsedCriteriaNode rootNode;
			if (topNodes.size() == 1) {
				rootNode = topNodes.get(0);
			} else {
				rootNode = new ParsedCriteriaNode(
						CriteriaNodeType.OPERATOR,
						CriteriaOperator.OR,
						false,
						topNodes,
						List.of()
				);
			}

			roots.add(new ParsedCriteriaRoot(rootGroupNo, rootNode));
			rootGroupNo++;
		}

		return new CriteriaParseBundle(new ArrayList<>(affected), roots);
	}

	private ParsedCriteriaNode toParsedCriteriaNode(
			NvdCveResponse.Node node,
			Set<AffectedSpec> affectedOut
	) {
		if (node == null) return null;

		List<ParsedCriteriaNode> children = new ArrayList<>();

		if (node.children() != null) {
			for (NvdCveResponse.Node child : node.children()) {
				ParsedCriteriaNode parsedChild = toParsedCriteriaNode(child, affectedOut);
				if (parsedChild != null) {
					children.add(parsedChild);
				}
			}
		}

		if (node.nodes() != null) {
			for (NvdCveResponse.Node child : node.nodes()) {
				ParsedCriteriaNode parsedChild = toParsedCriteriaNode(child, affectedOut);
				if (parsedChild != null) {
					children.add(parsedChild);
				}
			}
		}

		List<ParsedCriteriaCpe> leafCpes = new ArrayList<>();
		if (node.cpeMatch() != null) {
			for (NvdCveResponse.CpeMatch m : node.cpeMatch()) {
				ParsedCriteriaCpe parsedCpe = toParsedCriteriaCpe(m, affectedOut);
				if (parsedCpe != null) {
					leafCpes.add(parsedCpe);
				}
			}
		}

		boolean negate = Boolean.TRUE.equals(node.negate());
		CriteriaOperator operator = parseCriteriaOperator(node.operator());

		if (children.isEmpty() && leafCpes.isEmpty()) {
			return null;
		}

		if (children.isEmpty()) {
			return new ParsedCriteriaNode(
					CriteriaNodeType.LEAF_GROUP,
					null,
					negate,
					List.of(),
					leafCpes
			);
		}

		if (!leafCpes.isEmpty()) {
			children.add(new ParsedCriteriaNode(
					CriteriaNodeType.LEAF_GROUP,
					null,
					false,
					List.of(),
					leafCpes
			));
		}

		return new ParsedCriteriaNode(
				CriteriaNodeType.OPERATOR,
				operator == null ? CriteriaOperator.OR : operator,
				negate,
				children,
				List.of()
		);
	}

	private ParsedCriteriaCpe toParsedCriteriaCpe(
			NvdCveResponse.CpeMatch m,
			Set<AffectedSpec> affectedOut
	) {
		if (m == null) return null;
		if (Boolean.FALSE.equals(m.vulnerable())) return null;

		String criteria = normalize(m.criteria());
		if (criteria == null || !criteria.startsWith("cpe:2.3:")) return null;

		String vendorNorm = null;
		String productNorm = null;
		Long vendorId = null;
		Long productId = null;

		String cpePart = null;
		String targetSw = null;
		String targetHw = null;

		var parsedOpt = cpeNameParser.parse(criteria);
		if (parsedOpt.isPresent()) {
			var parsed = parsedOpt.get();

			cpePart = normalizeCpePart(parsed.part());
			targetSw = normalizeTargetSw(parsed.targetSw());
			targetHw = normalizeTargetHw(parsed.targetHw());

			vendorNorm = normalizer.normalizeVendor(parsed.vendor());
			productNorm = normalizer.normalizeProduct(parsed.product());

			if (vendorNorm != null && productNorm != null) {
				vendorId = cpeVendorRepository.findByNameNorm(vendorNorm)
						.map(v -> v.getId())
						.orElse(null);
				if (vendorId != null) {
					productId = cpeProductRepository.findByVendorIdAndNameNorm(vendorId, productNorm)
							.map(p -> p.getId())
							.orElse(null);
				}
			}
		}

		String vsi = nullToEmpty(normalize(m.versionStartIncluding()));
		String vse = nullToEmpty(normalize(m.versionStartExcluding()));
		String vei = nullToEmpty(normalize(m.versionEndIncluding()));
		String vee = nullToEmpty(normalize(m.versionEndExcluding()));

		affectedOut.add(new AffectedSpec(
				criteria,
				vendorId,
				productId,
				vendorNorm,
				productNorm,
				cpePart,
				targetSw,
				targetHw,
				vsi,
				vse,
				vei,
				vee
		));

		return new ParsedCriteriaCpe(
				criteria,
				vendorId,
				productId,
				vendorNorm,
				productNorm,
				cpePart,
				targetSw,
				targetHw,
				vsi,
				vse,
				vei,
				vee,
				true
		);
	}

	private static String pickEnDescription(List<NvdCveResponse.LangString> descriptions) {
		if (descriptions == null || descriptions.isEmpty()) return null;

		for (var d : descriptions) {
			if (d == null) continue;
			if ("en".equalsIgnoreCase(d.lang())) {
				String v = normalize(d.value());
				if (v != null) return v;
			}
		}
		for (var d : descriptions) {
			if (d == null) continue;
			String v = normalize(d.value());
			if (v != null) return v;
		}
		return null;
	}

	private static CvssPick pickCvss(NvdCveResponse.Metrics metrics) {
		if (metrics == null) return new CvssPick(null, null);

		if (metrics.cvssMetricV31() != null && !metrics.cvssMetricV31().isEmpty()) {
			var m = metrics.cvssMetricV31().get(0);
			if (m != null && m.cvssData() != null) {
				return new CvssPick(normalize(m.cvssData().version()), m.cvssData().baseScore());
			}
		}
		if (metrics.cvssMetricV30() != null && !metrics.cvssMetricV30().isEmpty()) {
			var m = metrics.cvssMetricV30().get(0);
			if (m != null && m.cvssData() != null) {
				return new CvssPick(normalize(m.cvssData().version()), m.cvssData().baseScore());
			}
		}
		return new CvssPick(null, null);
	}

	private static LocalDateTime parseNvdDateTime(String s) {
		String v = normalize(s);
		if (v == null) return null;

		try {
			return OffsetDateTime.parse(v).toLocalDateTime();
		} catch (Exception ignore) {}

		try {
			return java.time.Instant.parse(v).atOffset(java.time.ZoneOffset.UTC).toLocalDateTime();
		} catch (Exception ignore) {}

		try {
			return LocalDateTime.parse(v);
		} catch (Exception e) {
			return null;
		}
	}

	private static CriteriaOperator parseCriteriaOperator(String raw) {
		String s = normalize(raw);
		if (s == null) return null;
		try {
			return CriteriaOperator.valueOf(s.toUpperCase(Locale.ROOT));
		} catch (Exception ex) {
			return null;
		}
	}

	private static String normalize(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}

	private static String normalizeTargetSw(String raw) {
		String s = normalize(raw);
		if (s == null) {
			return null;
		}

		String x = s.toLowerCase(Locale.ROOT);
		return switch (x) {
			case "windows", "microsoft_windows" -> "windows";
			case "mac_os", "macos", "mac_os_x", "darwin" -> "mac_os";
			case "linux", "gnu_linux" -> "linux";
			case "iphone_os", "ios", "ipad_os", "android" -> x;
			case "*", "-" -> x;
			default -> x;
		};
	}

	private static String normalizeTargetHw(String raw) {
		String s = normalize(raw);
		if (s == null) {
			return null;
		}
		return s.toLowerCase(Locale.ROOT);
	}

	private static String normalizeCpePart(String raw) {
		String s = normalize(raw);
		if (s == null) {
			return null;
		}

		String x = s.toLowerCase(Locale.ROOT);
		return switch (x) {
			case "a", "o", "h" -> x;
			default -> x;
		};
	}

	private static String nullToEmpty(String s) {
		return (s == null) ? "" : s;
	}

	private record CvssPick(String version, BigDecimal score) {}

	private record AffectedSpec(
			String criteria,
			Long vendorId,
			Long productId,
			String vendorNorm,
			String productNorm,
			String cpePart,
			String targetSw,
			String targetHw,
			String versionStartIncluding,
			String versionStartExcluding,
			String versionEndIncluding,
			String versionEndExcluding
	) {}

	private record ParsedCriteriaRoot(
			int rootGroupNo,
			ParsedCriteriaNode rootNode
	) {}

	private record ParsedCriteriaNode(
			CriteriaNodeType nodeType,
			CriteriaOperator operator,
			boolean negate,
			List<ParsedCriteriaNode> children,
			List<ParsedCriteriaCpe> cpes
	) {}

	private record ParsedCriteriaCpe(
			String cpeName,
			Long cpeVendorId,
			Long cpeProductId,
			String vendorNorm,
			String productNorm,
			String cpePart,
			String targetSw,
			String targetHw,
			String versionStartIncluding,
			String versionStartExcluding,
			String versionEndIncluding,
			String versionEndExcluding,
			boolean matchVulnerable
	) {}

	private record CriteriaParseBundle(
			List<AffectedSpec> affected,
			List<ParsedCriteriaRoot> roots
	) {}

	public record ImportResult(int vulnerabilitiesUpserted, int affectedCpesInserted, int fetched) {}
}