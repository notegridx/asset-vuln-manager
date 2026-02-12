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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.domain.VulnerabilityAffectedCpe;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdClient;
import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityAffectedCpeRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;


@Service
public class NvdImportService {

	private static final Logger log = LoggerFactory.getLogger(NvdImportService.class);

	private final NvdClient nvdClient;
	private final VulnerabilityRepository vulnerabilityRepository;
	private final VulnerabilityAffectedCpeRepository affectedCpeRepository;

	public NvdImportService(
			NvdClient nvdClient,
			VulnerabilityRepository vulnerabilityRepository, VulnerabilityAffectedCpeRepository affectedCpeRepository) {
		this.nvdClient = nvdClient;
		this.vulnerabilityRepository = vulnerabilityRepository;
		this.affectedCpeRepository = affectedCpeRepository;
	}

	@Transactional
	public ImportResult importFromNvd(OffsetDateTime lastModStart, OffsetDateTime lastModEnd, int maxResults) {
		final String source = "NVD";

		int safeMax = Math.max(1, Math.min(maxResults, 2000));
		log.info("NVD import start: range={}..{}, maxResults={}", lastModStart, lastModEnd, safeMax);

		List<NvdCveResponse.VulnerabilityItem> items = nvdClient.fetchByLastModifiedRange(lastModStart, lastModEnd,
				safeMax);

		int vulnUpserted = 0;
		int affectedInserted = 0;

		for (NvdCveResponse.VulnerabilityItem item : items) {
			if (item == null || item.cve() == null)
				continue;

			String cveId = normalize(item.cve().id());
			if (cveId == null)
				continue;

			Vulnerability v = vulnerabilityRepository.findBySourceAndExternalId(source, cveId)
					.orElseGet(() -> new Vulnerability(source, cveId));

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
					lastModifiedAt);

			vulnerabilityRepository.save(v);
			vulnUpserted++;

			Set<String> cpes = extractCpes(item.cve().configurations());

			for (String cpe : cpes) {
				boolean exists;
				try {
					exists = affectedCpeRepository.existsByVulnerabilityIdAndCpeName(v.getId(), cpe);
				} catch (Exception ignore) {
					exists = false;
				}

				if (exists)
					continue;

				try {
					affectedCpeRepository.save(new VulnerabilityAffectedCpe(v, cpe));
					affectedInserted++;
				} catch (DataIntegrityViolationException e) {
					log.debug("AffectedCpe already exists (ignored). cveId={}, cpe={}", cveId, cpe);
				}

			}
		}

	

	log.info("NVD import done: vulnerabilitiesUpserted={}, affectedCpesInserted={}, fetched={}",vulnUpserted,affectedInserted,items.size());

	return new ImportResult(vulnUpserted,affectedInserted,items.size());
	}

	private static String pickEnDescription(List<NvdCveResponse.LangString> descriptions) {
		if (descriptions == null || descriptions.isEmpty())
			return null;

		for (var d : descriptions) {
			if (d == null)
				continue;
			if ("en".equalsIgnoreCase(d.lang())) {
				String v = normalize(d.value());
				if (v != null)
					return v;
			}
		}

		for (var d : descriptions) {
			if (d == null)
				continue;
			String v = normalize(d.value());
			if (v != null)
				return v;
		}

		return null;
	}

	private static CvssPick pickCvss(NvdCveResponse.Metrics metrics) {
		if (metrics == null)
			return new CvssPick(null, null);

		// v3.1
		if (metrics.cvssMetricV31() != null && !metrics.cvssMetricV31().isEmpty())

		{
			var m = metrics.cvssMetricV31().get(0);
			if (m != null && m.cvssData() != null) {
				return new CvssPick(normalize(m.cvssData().version()), m.cvssData().baseScore());
			}
		}

		// v3.0
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
		if (v == null)
			return null;
		try {
			return OffsetDateTime.parse(v).toLocalDateTime();
		} catch (DateTimeParseException e) {
			return null;
		}
	}

	private static Set<String> extractCpes(List<NvdCveResponse.Configurations> configurationsList) {
		Set<String> out = new LinkedHashSet<>();
		if (configurationsList == null || configurationsList.isEmpty()) return out;
		for (var configurations : configurationsList) {
			if (configurations == null || configurations.nodes() == null) continue;
			for (var n : configurations.nodes()) collectFromNode(n, out);
		}
		out.removeIf(Objects::isNull);
		out.removeIf(c -> !c.startsWith("cpe:2.3:"));
		return out;
	}

	private static void collectFromNode(NvdCveResponse.Node node, Set<String> out) {
		if (node == null)
			return;

		if (node.cpeMatch() != null) {
			for (var m : node.cpeMatch()) {
				if (m == null)
					continue;
				if (Boolean.FALSE.equals(m.vulnerable()))
					continue;

				String criteria = normalize(m.criteria());
				if (criteria != null)
					out.add(criteria);
			}
		}
		if (node.children() != null) {
			for (var c : node.children()) {
				collectFromNode(c, out);
			}
		}
	}
	
	private static String normalize(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}

	private record CvssPick(String version, BigDecimal score) {
	}

	public record ImportResult(int vulnerabilitiesUpserted, int affectedCpesInserted, int fetched) {
	}
}
