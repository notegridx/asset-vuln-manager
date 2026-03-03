package dev.notegridx.security.assetvulnmanager.infra.kev;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.Optional;

import org.springframework.stereotype.Component;

@Component
public class CisaKevClient {

    private static final String KEV_URL =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public record FetchResult(
            int statusCode,
            byte[] body,
            String etag,
            String lastModified
    ) {
        public boolean notModified() { return statusCode == 304; }
        public boolean ok() { return statusCode >= 200 && statusCode < 300; }
    }

    public FetchResult fetch(String ifNoneMatch, String ifModifiedSince) throws IOException, InterruptedException {

        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(KEV_URL))
                .timeout(Duration.ofSeconds(30))
                .GET();

        if (ifNoneMatch != null && !ifNoneMatch.isBlank()) {
            b.header("If-None-Match", ifNoneMatch);
        }
        if (ifModifiedSince != null && !ifModifiedSince.isBlank()) {
            b.header("If-Modified-Since", ifModifiedSince);
        }

        HttpResponse<byte[]> res = http.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());

        String etag = firstHeader(res, "ETag");
        String lm = firstHeader(res, "Last-Modified");

        byte[] body = (res.statusCode() == 304) ? null : res.body();
        return new FetchResult(res.statusCode(), body, etag, lm);
    }

    private static String firstHeader(HttpResponse<?> res, String name) {
        Optional<String> v = res.headers().firstValue(name);
        return v.orElse(null);
    }
}