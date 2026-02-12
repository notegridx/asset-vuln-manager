package dev.notegridx.security.assetvulnmanager.infra.nvd;


import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import reactor.core.publisher.Mono;

@Component
public class NvdClient {
	
	private static final Logger log = LoggerFactory.getLogger(NvdClient.class);
	
	private final WebClient webClient;
	private final String apiKey;
	
	public NvdClient(
			WebClient.Builder builder,
			@Value("${app.nvd.base-url}") String baseUrl,
			@Value("${app.nvd.api-key}") String apiKey
			) {
		this.apiKey = apiKey;
		this.webClient = builder
				.baseUrl(baseUrl)
				.defaultHeader(HttpHeaders.USER_AGENT, "asset-vuln-manager")
				.build();
	}
	
	public List<NvdCveResponse.VulnerabilityItem> fetchByLastModifiedRange(
			OffsetDateTime start,
			OffsetDateTime end,
			int maxResults
			) {
		int pageSize = Math.min(Math.max(maxResults, 1), 2000);
		int startIndex = 0;
		
		List<NvdCveResponse.VulnerabilityItem> out = new ArrayList<>();
		while (out.size() < maxResults) {
			NvdCveResponse resp = fetchCves(start, end, pageSize, startIndex).block();
			if (resp == null || resp.vulnerabilities() == null || resp.vulnerabilities().isEmpty()) break;
			
			out.addAll(resp.vulnerabilities());
			
			startIndex += resp.resultsPerPage();
			if (startIndex >= resp.totalResults()) break;
		}
		
		return out.size() > maxResults ? out.subList(0, maxResults) : out;
	}
	
	public Mono<NvdCveResponse> fetchCves(
			OffsetDateTime start,
			OffsetDateTime end,
			int resultsPerPage,
			int startIndex
			) {
		
		Instant startInstant = start.toInstant().truncatedTo(ChronoUnit.MILLIS);
		Instant endInstant = end.toInstant().truncatedTo(ChronoUnit.MILLIS);
		
		String startStr = DateTimeFormatter.ISO_INSTANT.format(startInstant);
		String endStr = DateTimeFormatter.ISO_INSTANT.format(endInstant);
		
		return webClient.get()
				.uri(uriBuilder -> {
					var b = uriBuilder
						.path("/rest/json/cves/2.0")
						.queryParam("lastModStartDate", startStr)
						.queryParam("lastModEndDate", endStr)						
						.queryParam("resultsPerPage", resultsPerPage)
						.queryParam("startIndex", startIndex);
					
					var uri = b.build();
					log.info("NVD request: {}", uri);
					return uri;
				})
				.headers(h -> {
					
					if (apiKey != null && !apiKey.isBlank()) h.set("apiKey", apiKey);
				})
				.exchangeToMono(res -> {
					HttpStatusCode status = res.statusCode();
					
					if (status.is2xxSuccessful()) {
						return res.bodyToMono(NvdCveResponse.class);
					}
					
					return res.bodyToMono(String.class)
							.defaultIfEmpty("")
							.flatMap(body -> {
								log.error("NVD error: status={}, headers ={}, body={}", status.value(), res.headers().asHttpHeaders(), body);
								return Mono.error(new IllegalStateException("NVD request failed. status=" + status.value()));
										
							});
				});
	}


}
