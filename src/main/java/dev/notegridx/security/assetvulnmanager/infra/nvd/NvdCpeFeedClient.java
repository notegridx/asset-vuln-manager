package dev.notegridx.security.assetvulnmanager.infra.nvd;

import io.netty.channel.ChannelOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.util.retry.Retry;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeoutException;

@Component
public class NvdCpeFeedClient {

    private static final Logger log = LoggerFactory.getLogger(NvdCpeFeedClient.class);

    private final WebClient webClient;

    private final String baseUrl;
    private final String metaPath;
    private final String gzPath;

    private final Duration metaTimeout;
    private final Duration downloadTimeout;
    private final Duration responseTimeout;
    private final int maxRetries;

    public NvdCpeFeedClient(
            WebClient.Builder builder,
            @Value("${app.nvd.cpe.base-url}") String baseUrl,
            @Value("${app.nvd.cpe.meta-path}") String metaPath,
            @Value("${app.nvd.cpe.gz-path}") String gzPath,
            @Value("${app.nvd.cpe.meta-timeout-seconds:60}") long metaTimeoutSeconds,
            @Value("${app.nvd.cpe.download-timeout-minutes:20}") long downloadTimeoutMinutes,
            @Value("${app.nvd.cpe.connect-timeout-millis:30000}") int connectTimeoutMillis,
            @Value("${app.nvd.cpe.response-timeout-seconds:120}") long responseTimeoutSeconds,
            @Value("${app.nvd.cpe.max-retries:3}") int maxRetries
    ) {
        this.baseUrl = baseUrl;
        this.metaPath = metaPath;
        this.gzPath = gzPath;
        this.metaTimeout = Duration.ofSeconds(Math.max(10, metaTimeoutSeconds));
        this.downloadTimeout = Duration.ofMinutes(Math.max(1, downloadTimeoutMinutes));
        this.responseTimeout = Duration.ofSeconds(Math.max(10, responseTimeoutSeconds));
        this.maxRetries = Math.max(0, maxRetries);

        HttpClient httpClient = HttpClient.create()
                .compress(true)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, Math.max(1_000, connectTimeoutMillis))
                .responseTimeout(this.responseTimeout);

        this.webClient = builder
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .defaultHeader(HttpHeaders.USER_AGENT, "asset-vuln-manager")
                .build();
    }

    /**
     * META fetch is small -> byte[] is OK.
     */
    public CpeFeedMetaParser.FeedMeta fetchMeta(CpeFeedMetaParser metaParser) throws IOException {
        try {
            byte[] body = webClient.get()
                    .uri(metaPath)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, response ->
                            response.bodyToMono(String.class)
                                    .defaultIfEmpty("")
                                    .flatMap(bodyText -> Mono.error(new IOException(
                                            "CPE META fetch failed. status=" + response.statusCode().value()
                                                    + ", path=" + metaPath
                                                    + ", body=" + abbreviate(bodyText, 300)
                                    )))
                    )
                    .bodyToMono(byte[].class)
                    .timeout(metaTimeout)
                    .retryWhen(buildRetry("cpe-meta", metaPath))
                    .block();

            if (body == null) {
                throw new IOException("META fetch returned empty body. path=" + metaPath);
            }

            return metaParser.parse(new ByteArrayInputStream(body));

        } catch (Exception e) {
            throw new IOException(
                    "Failed to fetch CPE meta. baseUrl=" + baseUrl
                            + ", path=" + metaPath
                            + ", err=" + safeMsg(unwrap(e)),
                    unwrap(e)
            );
        }
    }

    /**
     * Large tar.gz must NOT be buffered into byte[].
     * Stream to a temp file using DataBufferUtils.write(...) and return the Path.
     */
    public Path downloadTarGzToTempFile() throws IOException {
        Path tmp = null;

        try {
            tmp = Files.createTempFile("nvdcpe-2.0-", ".tar.gz");

            Flux<DataBuffer> body = webClient.get()
                    .uri(gzPath)
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, response ->
                            response.bodyToMono(String.class)
                                    .defaultIfEmpty("")
                                    .flatMap(bodyText -> Mono.error(new IOException(
                                            "CPE tar.gz download failed. status=" + response.statusCode().value()
                                                    + ", path=" + gzPath
                                                    + ", body=" + abbreviate(bodyText, 300)
                                    )))
                    )
                    .bodyToFlux(DataBuffer.class)
                    .retryWhen(buildRetry("cpe-gzip", gzPath));

            DataBufferUtils.write(body, tmp)
                    .timeout(downloadTimeout)
                    .block();

            long bytes = Files.exists(tmp) ? Files.size(tmp) : 0L;
            if (bytes <= 0) {
                safeDelete(tmp);
                throw new IOException("CPE tar.gz download returned empty file. path=" + tmp);
            }

            log.info("CPE tar.gz downloaded. path={}, bytes={}, source={}", tmp, bytes, gzPath);
            return tmp;

        } catch (Exception e) {
            Throwable cause = unwrap(e);
            if (tmp != null) {
                safeDelete(tmp);
            }
            throw new IOException(
                    "Failed to download CPE tar.gz to temp file. baseUrl=" + baseUrl
                            + ", path=" + gzPath
                            + ", err=" + safeMsg(cause),
                    cause
            );
        }
    }

    private Retry buildRetry(String label, String path) {
        if (maxRetries <= 0) {
            return Retry.max(0);
        }

        return Retry.backoff(maxRetries, Duration.ofSeconds(3))
                .maxBackoff(Duration.ofSeconds(30))
                .filter(this::isRetryable)
                .doBeforeRetry(signal -> {
                    Throwable failure = unwrap(signal.failure());
                    log.warn(
                            "Retrying {} request. attempt={}/{}, path={}, err={}",
                            label,
                            signal.totalRetries() + 1,
                            maxRetries,
                            path,
                            safeMsg(failure)
                    );
                })
                .onRetryExhaustedThrow((spec, signal) -> signal.failure());
    }

    private boolean isRetryable(Throwable t) {
        Throwable x = unwrap(t);

        if (x instanceof TimeoutException) {
            return true;
        }

        if (x instanceof IOException) {
            return true;
        }

        String msg = x.getMessage();
        if (msg == null) {
            return false;
        }

        String m = msg.toLowerCase();
        return m.contains("timeout")
                || m.contains("connection reset")
                || m.contains("premature close")
                || m.contains("connection refused")
                || m.contains("connection prematurely closed")
                || m.contains("503")
                || m.contains("502")
                || m.contains("504")
                || m.contains("429");
    }

    private static Throwable unwrap(Throwable t) {
        Throwable x = Exceptions.unwrap(t);
        if (x.getCause() != null
                && (x instanceof RuntimeException || x instanceof IOException)
                && x.getMessage() != null
                && x.getMessage().startsWith("#block terminated")) {
            return x.getCause();
        }
        return x;
    }

    private static void safeDelete(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (Exception ignore) {
        }
    }

    private static String safeMsg(Throwable t) {
        if (t == null) {
            return "unknown";
        }
        String m = t.getMessage();
        return (m == null || m.isBlank()) ? t.getClass().getSimpleName() : m;
    }

    private static String abbreviate(String s, int max) {
        if (s == null) {
            return null;
        }
        String t = s.trim().replaceAll("\\s+", " ");
        if (t.length() <= max) {
            return t;
        }
        return t.substring(0, max) + "...";
    }
}