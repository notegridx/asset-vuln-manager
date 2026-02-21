package dev.notegridx.security.assetvulnmanager.infra.nvd;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Component
public class NvdCveFeedClient {

    private final WebClient webClient;

    private final String baseUrl;

    private final String modifiedMetaPath;
    private final String modifiedGzPath;

    private final String recentMetaPath;
    private final String recentGzPath;

    // ★追加：年次パターン
    private final String yearMetaPathPattern;
    private final String yearGzPathPattern;

    public NvdCveFeedClient(
            WebClient.Builder builder,
            @Value("${app.nvd.cve.base-url:https://nvd.nist.gov}") String baseUrl,
            @Value("${app.nvd.cve.modified.meta-path:/feeds/json/cve/2.0/nvdcve-2.0-modified.meta}") String modifiedMetaPath,
            @Value("${app.nvd.cve.modified.gz-path:/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz}") String modifiedGzPath,
            @Value("${app.nvd.cve.recent.meta-path:/feeds/json/cve/2.0/nvdcve-2.0-recent.meta}") String recentMetaPath,
            @Value("${app.nvd.cve.recent.gz-path:/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz}") String recentGzPath,
            @Value("${app.nvd.cve.year.meta-path-pattern:/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta}") String yearMetaPathPattern,
            @Value("${app.nvd.cve.year.gz-path-pattern:/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz}") String yearGzPathPattern
    ) {
        this.baseUrl = baseUrl;
        this.modifiedMetaPath = modifiedMetaPath;
        this.modifiedGzPath = modifiedGzPath;
        this.recentMetaPath = recentMetaPath;
        this.recentGzPath = recentGzPath;
        this.yearMetaPathPattern = yearMetaPathPattern;
        this.yearGzPathPattern = yearGzPathPattern;

        this.webClient = builder
                .baseUrl(this.baseUrl)
                .build();
    }

    public enum FeedKind { MODIFIED, RECENT, YEAR }

    // 旧呼び出し互換：既存の fetchMeta(kind, parser) を生かす
    public CveFeedMetaParser.FeedMeta fetchMeta(FeedKind kind, CveFeedMetaParser parser) throws IOException {
        return fetchMeta(kind, null, parser);
    }

    public CveFeedMetaParser.FeedMeta fetchMeta(FeedKind kind, Integer year, CveFeedMetaParser parser) throws IOException {
        String path = resolveMetaPath(kind, year);

        byte[] bytes = webClient.get()
                .uri(path)
                .accept(MediaType.TEXT_PLAIN)
                .retrieve()
                .bodyToMono(byte[].class)
                .block();

        if (bytes == null) throw new IOException("meta download returned null. kind=" + kind + " year=" + year);

        try (InputStream in = new java.io.ByteArrayInputStream(bytes)) {
            return parser.parse(in);
        }
    }

    /**
     * Download json.gz into a temp file. Caller should delete it.
     */
    // 旧呼び出し互換
    public Path downloadJsonGzToTempFile(FeedKind kind) throws IOException {
        return downloadJsonGzToTempFile(kind, null);
    }

    public Path downloadJsonGzToTempFile(FeedKind kind, Integer year) throws IOException {
        String path = resolveGzPath(kind, year);

        String suffix = switch (kind) {
            case RECENT -> "recent";
            case MODIFIED -> "modified";
            case YEAR -> String.valueOf(requireYear(year));
        };

        Path tmp = Files.createTempFile("nvdcve-2.0-" + suffix + "-", ".json.gz");

        try {
            Mono<Void> done = webClient.get()
                    .uri(path)
                    .retrieve()
                    .bodyToFlux(org.springframework.core.io.buffer.DataBuffer.class)
                    .as(flux -> DataBufferUtils.write(
                            flux,
                            tmp,
                            StandardOpenOption.TRUNCATE_EXISTING
                    ))
                    .then();

            done.block();
            return tmp;

        } catch (Exception e) {
            try { Files.deleteIfExists(tmp); } catch (Exception ignore) {}
            if (e instanceof IOException io) throw io;
            throw new IOException("Failed to download json.gz. kind=" + kind + " year=" + year + " err=" + e.getMessage(), e);
        }
    }

    private String resolveMetaPath(FeedKind kind, Integer year) throws IOException {
        return switch (kind) {
            case RECENT -> recentMetaPath;
            case MODIFIED -> modifiedMetaPath;
            case YEAR -> yearMetaPathPattern.replace("{year}", String.valueOf(requireYear(year)));
        };
    }

    private String resolveGzPath(FeedKind kind, Integer year) throws IOException {
        return switch (kind) {
            case RECENT -> recentGzPath;
            case MODIFIED -> modifiedGzPath;
            case YEAR -> yearGzPathPattern.replace("{year}", String.valueOf(requireYear(year)));
        };
    }

    private int requireYear(Integer year) throws IOException {
        if (year == null) throw new IOException("year is required when kind=YEAR");
        // 雑に防御（必要なら範囲は後で調整）
        if (year < 1999 || year > 2100) throw new IOException("invalid year=" + year);
        return year;
    }
}
