package dev.notegridx.security.assetvulnmanager.infra.nvd;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;


import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

@Component
public class NvdCpeFeedClient {

    private final WebClient webClient;

    private final String metaPath;
    private final String gzPath;

    public NvdCpeFeedClient(
            WebClient.Builder builder,
            @Value("${app.nvd.cpe.base-url}") String baseUrl,
            @Value("${app.nvd.cpe.meta-path}") String metaPath,
            @Value("${app.nvd.cpe.gz-path}") String gzPath
    ) {
        this.metaPath = metaPath;
        this.gzPath = gzPath;

        this.webClient = builder
                .baseUrl(baseUrl)
                .defaultHeader(HttpHeaders.USER_AGENT, "asset-vuln-manager")
                .build();
    }

    /**
     * META fetch is small -> byte[] is OK (as-is requirement).
     */
    public CpeFeedMetaParser.FeedMeta fetchMeta(CpeFeedMetaParser metaParser) throws IOException {
        byte[] body = webClient.get()
                .uri(metaPath)
                .retrieve()
                .bodyToMono(byte[].class)
                .timeout(Duration.ofSeconds(60))
                .block();

        if (body == null) throw new IOException("META fetch returned empty body");
        return metaParser.parse(new ByteArrayInputStream(body));
    }

    /**
     * Large tar.gz must NOT be buffered into byte[].
     * Stream to a temp file using DataBufferUtils.write(...) and return the Path.
     * <p>
     * Requirements:
     * - bodyToFlux(DataBuffer)
     * - DataBufferUtils.write to temp file
     * - timeout ~10 minutes
     * - ensure size > 0
     * - on failure delete temp and throw IOException
     */
    public Path downloadTarGzToTempFile() throws IOException {
        Path tmp = null;
        try {
            tmp = Files.createTempFile("nvdcpe-2.0-", ".tar.gz");

            Flux<DataBuffer> body = webClient.get()
                    .uri(gzPath)
                    .retrieve()
                    .bodyToFlux(DataBuffer.class);

            DataBufferUtils.write(body, tmp)
                    .timeout(Duration.ofMinutes(10))
                    .block();

            long bytes = Files.exists(tmp) ? Files.size(tmp) : 0L;
            if (bytes <= 0) {
                safeDelete(tmp);
                throw new IOException("CPE tar.gz download returned empty file. path=" + tmp);
            }

            return tmp;

        } catch (
                Exception e) {
            if (tmp != null) safeDelete(tmp);
            if (e instanceof IOException io) throw io;
            throw new IOException("Failed to download CPE tar.gz to temp file. " + safeMsg(e), e);
        }
    }

    private static void safeDelete(Path p) {
        try {
            Files.deleteIfExists(p);
        } catch (Exception ignore) {
        }
    }

    private static String safeMsg(Throwable t) {
        String m = t.getMessage();
        return (m == null) ? t.getClass().getSimpleName() : m;
    }

}
