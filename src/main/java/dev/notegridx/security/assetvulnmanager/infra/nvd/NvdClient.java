package dev.notegridx.security.assetvulnmanager.infra.nvd;

import java.time.Duration;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import dev.notegridx.security.assetvulnmanager.infra.nvd.dto.NvdCveResponse;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

@Component
public class NvdClient {

	private static final Logger log = LoggerFactory.getLogger(NvdClient.class);

	// ---- Paging / throttling / retry policy ----
	// Page size must be kept modest to avoid huge JSON payloads and in-memory buffering issues.
	private static final int DEFAULT_RESULTS_PER_PAGE = 50;

	// Be nice to NVD: throttle requests
	private static final Duration THROTTLE_WITHOUT_KEY = Duration.ofSeconds(7);
	private static final Duration THROTTLE_WITH_KEY = Duration.ofMillis(750);

	// Retry on 429/503 with backoff (Retry-After is respected when present)
	private static final int RETRY_MAX_ATTEMPTS = 6; // total attempts = 1 + retries
	private static final Duration RETRY_BASE_BACKOFF = Duration.ofSeconds(2);
	private static final Duration RETRY_MAX_BACKOFF = Duration.ofSeconds(30);

	private final WebClient webClient;
	private final String apiKey;

	public NvdClient(
			WebClient.Builder builder,
			@Value("${app.nvd.base-url:https://services.nvd.nist.gov}") String baseUrl,
			@Value("${app.nvd.api-key:}") String apiKey
	) {
		this.apiKey = apiKey;
		this.webClient = builder
				.baseUrl(baseUrl)
				.defaultHeader(HttpHeaders.ACCEPT, "application/json")
				.build();
	}

	public List<NvdCveResponse.VulnerabilityItem> fetchByLastModifiedRange(
			OffsetDateTime start,
			OffsetDateTime end,
			int maxResults
	) {
		int safeMax = Math.max(maxResults, 1);

		// IMPORTANT: Separate maxResults (overall cap) from resultsPerPage (payload size control).
		int pageSize = DEFAULT_RESULTS_PER_PAGE;
		int startIndex = 0;

		List<NvdCveResponse.VulnerabilityItem> out = new ArrayList<>();
		while (out.size() < safeMax) {
			int remaining = safeMax - out.size();
			int limit = Math.min(pageSize, remaining);

			NvdCveResponse resp = fetchCves(start, end, limit, startIndex).block();
			if (resp == null || resp.vulnerabilities() == null || resp.vulnerabilities().isEmpty()) break;

			out.addAll(resp.vulnerabilities());

			int received = resp.vulnerabilities().size();
			startIndex += received;

			// Safety: if server returns fewer items than requested, move on; if none, stop.
			if (received <= 0) break;
			if (startIndex >= resp.totalResults()) break;
		}

		return out.size() > safeMax ? out.subList(0, safeMax) : out;
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

		Duration throttle = (apiKey != null && !apiKey.isBlank()) ? THROTTLE_WITH_KEY : THROTTLE_WITHOUT_KEY;

		Mono<NvdCveResponse> request = webClient.get()
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

					// Retryable statuses (be nice + robust): 429 Too Many Requests, 503 Service Unavailable
					if (status.value() == HttpStatus.TOO_MANY_REQUESTS.value()
							|| status.value() == HttpStatus.SERVICE_UNAVAILABLE.value()) {
						Duration retryAfter = parseRetryAfter(res.headers().asHttpHeaders());
						return res.bodyToMono(String.class)
								.defaultIfEmpty("")
								.flatMap(body -> {
									log.warn("NVD retryable error: status={}, retryAfter={}, headers={}, body={}",
											status.value(), retryAfter, res.headers().asHttpHeaders(), abbreviate(body, 800));
									return Mono.error(new NvdRetryableException(status.value(), retryAfter));
								});
					}

					// Non-retryable: log and fail fast
					return res.bodyToMono(String.class)
							.defaultIfEmpty("")
							.flatMap(body -> {
								log.error("NVD error: status={}, headers={}, body={}",
										status.value(), res.headers().asHttpHeaders(), abbreviate(body, 1200));
								return Mono.error(new IllegalStateException("NVD request failed. status=" + status.value()));
							});
				});

		// Throttle requests to respect NVD rate limits, especially strict without API key.
		return request
				.delaySubscription(throttle)
				.retryWhen(retrySpec());
	}

	// ---- Retry helpers ----

	private Retry retrySpec() {
		return Retry.from(companion ->
				companion
						.zipWith(Flux.range(1, RETRY_MAX_ATTEMPTS), (signal, attempt) -> new RetryCtx(signal.failure(), attempt))
						.flatMap(ctx -> {
							Throwable ex = ctx.ex;
							int attempt = ctx.attempt;

							if (!(ex instanceof NvdRetryableException re)) {
								return Mono.error(ex);
							}

							// Stop after max attempts
							if (attempt >= RETRY_MAX_ATTEMPTS) {
								log.warn("NVD retry exhausted: attempts={}, lastStatus={}", attempt, re.statusCode);
								return Mono.error(ex);
							}

							Duration wait = (re.retryAfter != null) ? re.retryAfter : backoff(attempt);
							log.warn("Retrying NVD request: attempt={}, wait={}, status={}", attempt, wait, re.statusCode);
							return Mono.delay(wait);
						})
		);
	}

	private static Duration backoff(int attempt) {
		// attempt is 1..N; exponential backoff with cap
		long factor = 1L << Math.min(attempt, 10); // cap shift to avoid overflow
		Duration d = RETRY_BASE_BACKOFF.multipliedBy(factor);
		if (d.compareTo(RETRY_MAX_BACKOFF) > 0) d = RETRY_MAX_BACKOFF;

		// tiny deterministic jitter to avoid herding (no Random needed)
		long jitterMs = (attempt * 137L) % 250L; // 0..249ms
		return d.plusMillis(jitterMs);
	}

	private static Duration parseRetryAfter(HttpHeaders headers) {
		// Prefer Retry-After header when present (seconds form is common)
		String v = headers.getFirst("Retry-After");
		if (v == null || v.isBlank()) return null;
		v = v.trim();

		// Most servers send delta-seconds. If it's a date, ignore for now.
		try {
			long seconds = Long.parseLong(v);
			if (seconds <= 0) return Duration.ofSeconds(1);
			return Duration.ofSeconds(Math.min(seconds, 120)); // cap to 2 minutes
		} catch (NumberFormatException ignore) {
			return null;
		}
	}

	private static String abbreviate(String s, int max) {
		if (s == null) return null;
		String t = s.trim();
		if (t.length() <= max) return t;
		return t.substring(0, max) + "...";
	}

	private static final class RetryCtx {
		final Throwable ex;
		final int attempt;

		RetryCtx(Throwable ex, int attempt) {
			this.ex = ex;
			this.attempt = attempt;
		}
	}

	private static final class NvdRetryableException extends RuntimeException {
		final int statusCode;
		final Duration retryAfter;

		NvdRetryableException(int statusCode, Duration retryAfter) {
			super("NVD retryable error. status=" + statusCode);
			this.statusCode = statusCode;
			this.retryAfter = retryAfter;
		}
	}
}
