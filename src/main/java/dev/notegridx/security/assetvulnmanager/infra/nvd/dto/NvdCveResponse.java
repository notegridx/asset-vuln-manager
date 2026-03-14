package dev.notegridx.security.assetvulnmanager.infra.nvd.dto;

import java.math.BigDecimal;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record NvdCveResponse(
		int resultsPerPage,
		int startIndex,
		int totalResults,
		List<VulnerabilityItem> vulnerabilities
) {

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record VulnerabilityItem(
			Cve cve
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Cve(
			String id,
			List<LangString> descriptions,
			Metrics metrics,
			List<Configurations> configurations,
			String published,
			String lastModified
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record LangString(
			String lang,
			String value
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Metrics(
			List<CvssMetricV31> cvssMetricV31,
			List<CvssMetricV30> cvssMetricV30
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record CvssMetricV31(
			CvssData cvssData
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record CvssMetricV30(
			CvssData cvssData
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record CvssData(
			String version,
			BigDecimal baseScore
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Configurations(
			List<Node> nodes
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record Node(
			String operator,
			Boolean negate,
			List<CpeMatch> cpeMatch,
			List<Node> children,
			List<Node> nodes
	) {}

	@JsonIgnoreProperties(ignoreUnknown = true)
	public record CpeMatch(
			Boolean vulnerable,
			String criteria,
			String versionStartIncluding,
			String versionStartExcluding,
			String versionEndIncluding,
			String versionEndExcluding
	) {}
}