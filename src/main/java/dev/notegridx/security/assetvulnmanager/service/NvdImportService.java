package dev.notegridx.security.assetvulnmanager.service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.infra.nvd.CpeNameParser;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdClient;
import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;

@Service
public class NvdImportService {

	private static final Logger log = LoggerFactory.getLogger(NvdImportService.class);

	private static final String SOURCE_NVD = "NVD";
	private static final long SENTINEL_ID = -1L;

	private final NvdClient nvdClient;
	private final VulnerabilityRepository vulnerabilityRepository;
	private final VulnerabilityAffectedCpeRepository affectedCpeRepository;

	private final CpeNameParser cpeNameParser;
	private final VendorProductNormalizer normalizer;
	private final CpeVendorRepository cpeVendorRepository;
	private final CpeProductRepository cpeProductRepository;

	public NvdImportService(
			NvdClient nvdClient,
			VulnerabilityRepository vulnerabilityRepository,
			VulnerabilityAffectedCpeRepository affectedCpeRepository,
			CpeNameParser cpeNameParser,
			VendorProductNormalizer normalizer,
			CpeVendorRepository cpeVendorRepository,
			CpeProductRepository cpeProductRepository
	) {
		this.nvdClient = nvdClient;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.affectedCpeRepository = affectedCpeRepository;
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
					null,
					desc,
					cvss.version(),
					cvss.score(),
					publishedAt,
					lastModifiedAt
			);

			vulnerabilityRepository.save(v);
			vulnUpserted++;

			Set<AffectedSpec> specs = extractAffectedSpecs(item.cve().configurations());

			for (AffectedSpec spec : specs) {

				// *_nn（NOT NULL）値を生成して exists 判定に使う（NULL問題を完全回避）
				long vendorIdNn = (spec.vendorId() != null) ? spec.vendorId() : SENTINEL_ID;
				long productIdNn = (spec.productId() != null) ? spec.productId() : SENTINEL_ID;

				String cpeNameNn = nullToEmpty(spec.criteria());
				String vendorNormNn = nullToEmpty(spec.vendorNorm());
				String productNormNn = nullToEmpty(spec.productNorm());
				String vStartIncNn = nullToEmpty(spec.versionStartIncluding());
				String vStartExcNn = nullToEmpty(spec.versionStartExcluding());
				String vEndIncNn = nullToEmpty(spec.versionEndIncluding());
				String vEndExcNn = nullToEmpty(spec.versionEndExcluding());

				boolean exists = affectedCpeRepository
						.existsByVulnerabilityIdAndCpeNameNnAndCpeVendorIdNnAndCpeProductIdNnAndVendorNormNnAndProductNormNnAndVersionStartIncludingNnAndVersionStartExcludingNnAndVersionEndIncludingNnAndVersionEndExcludingNn(
								v.getId(),
								cpeNameNn,
								vendorIdNn,
								productIdNn,
								vendorNormNn,
								productNormNn,
								vStartIncNn,
								vStartExcNn,
								vEndIncNn,
								vEndExcNn
						);

				if (exists) {
					continue;
				}

				affectedCpeRepository.save(new VulnerabilityAffectedCpe(
						v,
						spec.criteria(),
						spec.vendorId(),
						spec.productId(),
						spec.vendorNorm(),
						spec.productNorm(),
						spec.versionStartIncluding(),
						spec.versionStartExcluding(),
						spec.versionEndIncluding(),
						spec.versionEndExcluding()
				));
				affectedInserted++;
			}
		}

		log.info("NVD import done: vulnerabilitiesUpserted={}, affectedCpesInserted={}, fetched={}",
				vulnUpserted, affectedInserted, items.size());

		return new ImportResult(vulnUpserted, affectedInserted, items.size());
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

		// 1) ISO_OFFSET_DATE_TIME (e.g. 2026-02-22T18:00:01-05:00 / ...Z)
		try {
			return OffsetDateTime.parse(v).toLocalDateTime();
		} catch (Exception ignore) {}

		// 2) Instant (e.g. 2026-02-22T23:00:01Z)
		try {
			return java.time.Instant.parse(v).atOffset(java.time.ZoneOffset.UTC).toLocalDateTime();
		} catch (Exception ignore) {}

		// 3) LocalDateTime (no offset)
		try {
			return LocalDateTime.parse(v);
		} catch (Exception e) {
			// ✅ ここで初めてログ（1回だけでもOK）
			// log.warn("Failed to parse NVD datetime: [{}]", v);
			return null;
		}
	}

	private Set<AffectedSpec> extractAffectedSpecs(List<NvdCveResponse.Configurations> configurationsList) {
		Set<AffectedSpec> out = new LinkedHashSet<>();
		if (configurationsList == null || configurationsList.isEmpty()) return out;

		for (var configurations : configurationsList) {
			if (configurations == null || configurations.nodes() == null) continue;
			for (var n : configurations.nodes()) collectFromNode(n, out);
		}

		out.removeIf(Objects::isNull);
		out.removeIf(s -> s.criteria() == null || !s.criteria().startsWith("cpe:2.3:"));
		return out;
	}

	private void collectFromNode(NvdCveResponse.Node node, Set<AffectedSpec> out) {
		if (node == null) return;

		if (node.cpeMatch() != null) {
			for (var m : node.cpeMatch()) {
				if (m == null) continue;
				if (Boolean.FALSE.equals(m.vulnerable())) continue;

				String criteria = normalize(m.criteria());
				if (criteria == null) continue;

				String vendorNorm = null;
				String productNorm = null;
				Long vendorId = null;
				Long productId = null;

				var vpOpt = cpeNameParser.parseVendorProduct(criteria);
				if (vpOpt.isPresent()) {
					var vp = vpOpt.get();
					vendorNorm = normalizer.normalizeVendor(vp.vendor());
					productNorm = normalizer.normalizeProduct(vp.product());

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

				out.add(new AffectedSpec(
						criteria,
						vendorId,
						productId,
						vendorNorm,
						productNorm,
						normalize(m.versionStartIncluding()),
						normalize(m.versionStartExcluding()),
						normalize(m.versionEndIncluding()),
						normalize(m.versionEndExcluding())
				));
			}
		}

		if (node.children() != null) {
			for (var c : node.children()) collectFromNode(c, out);
		}
	}

	private static String normalize(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
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
			String versionStartIncluding,
			String versionStartExcluding,
			String versionEndIncluding,
			String versionEndExcluding
	) {}

	public record ImportResult(int vulnerabilitiesUpserted, int affectedCpesInserted, int fetched) {}
}