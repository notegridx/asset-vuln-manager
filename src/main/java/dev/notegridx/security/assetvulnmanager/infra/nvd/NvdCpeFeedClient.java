package dev.notegridx.security.assetvulnmanager.infra.nvd;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.io.ByteArrayInputStream;
import java.io.IOException;

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

    public byte[] downloadGz() throws IOException {
        byte[] gz = webClient.get()
                .uri(gzPath)
                .retrieve()
                .bodyToMono(byte[].class)
                .timeout(Duration.ofMinutes(5))
                .block();

        if (gz == null || gz.length == 0) throw new IOException("GZ download retuned empty body");
        return gz;
    }

    public Mono<byte[]> downloadsGzAsync() {
        return webClient.get()
                .uri(gzPath)
                .retrieve()
                .bodyToMono(byte[].class);
    }


}
