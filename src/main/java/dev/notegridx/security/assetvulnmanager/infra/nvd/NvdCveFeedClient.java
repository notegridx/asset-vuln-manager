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

/**
 * Downloads NVD CVE JSON 2.0 feeds (meta + json.gz) into a temp file (streaming-safe).
 *
 * You will provide concrete feed paths via application.yml, e.g.
 * - modified meta: /feeds/json/cve/2.0/nvdcve-2.0-modified.meta
 * - modified gz  : /feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz
 *
 * NOTE: This is intentionally similar in spirit to NvdCpeFeedClient.
 */
@Component
public class NvdCveFeedClient {

    private final WebClient webClient;

    private final String baseUrl;

    private final String modifiedMetaPath;
    private final String modifiedGzPath;

    private final String recentMetaPath;
    private final String recentGzPath;

    public NvdCveFeedClient(
            WebClient.Builder builder,
            @Value("${app.nvd.cve.base-url:https://nvd.nist.gov}") String baseUrl,
            @Value("${app.nvd.cve.modified.meta-path:/feeds/json/cve/2.0/nvdcve-2.0-modified.meta}") String modifiedMetaPath,
            @Value("${app.nvd.cve.modified.gz-path:/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz}") String modifiedGzPath,
            @Value("${app.nvd.cve.recent.meta-path:/feeds/json/cve/2.0/nvdcve-2.0-recent.meta}") String recentMetaPath,
            @Value("${app.nvd.cve.recent.gz-path:/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz}") String recentGzPath
    ) {
        this.baseUrl = baseUrl;
        this.modifiedMetaPath = modifiedMetaPath;
        this.modifiedGzPath = modifiedGzPath;
        this.recentMetaPath = recentMetaPath;
        this.recentGzPath = recentGzPath;

        this.webClient = builder
                .baseUrl(this.baseUrl)
                .build();
    }

    public enum FeedKind { MODIFIED, RECENT }

    public CveFeedMetaParser.FeedMeta fetchMeta(FeedKind kind, CveFeedMetaParser parser) throws IOException {
        String path = (kind == FeedKind.RECENT) ? recentMetaPath : modifiedMetaPath;

        byte[] bytes = webClient.get()
                .uri(path)
                .accept(MediaType.TEXT_PLAIN)
                .retrieve()
                .bodyToMono(byte[].class)
                .block();

        if (bytes == null) throw new IOException("meta download returned null. kind=" + kind);

        try (InputStream in = new java.io.ByteArrayInputStream(bytes)) {
            return parser.parse(in);
        }
    }

    /**
     * Download json.gz into a temp file. Caller should delete it.
     */
    public Path downloadJsonGzToTempFile(FeedKind kind) throws IOException {
        String path = (kind == FeedKind.RECENT) ? recentGzPath : modifiedGzPath;

        Path tmp = Files.createTempFile("nvdcve-2.0-" + kind.name().toLowerCase(), ".json.gz");

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
            throw new IOException("Failed to download json.gz. kind=" + kind + " err=" + e.getMessage(), e);
        }
    }
}
