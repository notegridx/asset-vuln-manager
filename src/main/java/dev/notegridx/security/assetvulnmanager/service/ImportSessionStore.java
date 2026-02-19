package dev.notegridx.security.assetvulnmanager.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class ImportSessionStore {

    private final Path baseDir;
    private final Duration ttl;

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public ImportSessionStore(
            @Value("${app.import.session-dir:}") String sessionDir,
            @Value("${app.import.session-ttl-minutes:30}") long ttlMinutes
    ) {
        String dir = (sessionDir == null) ? "" : sessionDir.trim();
        if (dir.isEmpty()) {
            dir = System.getProperty("java.io.tmpdir")
                    + "/asset-vuln-manager/import-sessions";
        }
        this.baseDir = Paths.get(dir);
        this.ttl = Duration.ofMinutes(Math.max(1, ttlMinutes));
    }

    public String save(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("file is empty");
        }
        ensureBaseDir();
        pruneExpired();

        String sessionId = UUID.randomUUID().toString();
        Path dst = baseDir.resolve(sessionId + ".csv");

        try (InputStream in = file.getInputStream()) {
            Files.copy(in, dst, StandardCopyOption.REPLACE_EXISTING);
        }

        sessions.put(sessionId, new Session(
                sessionId,
                dst,
                Instant.now(),
                safeName(file.getOriginalFilename())
        ));

        return sessionId;
    }

    public InputStream open(String sessionId) throws IOException {
        pruneExpired();

        Session s = sessions.get(sessionId);
        if (s == null) {
            throw new NoSuchFileException("Import session not found (expired?): " + sessionId);
        }
        if (!Files.exists(s.path())) {
            sessions.remove(sessionId);
            throw new NoSuchFileException("Import session file missing: " + s.path());
        }
        return Files.newInputStream(s.path(), StandardOpenOption.READ);
    }

    public void delete(String sessionId) {
        Session s = sessions.remove(sessionId);
        if (s == null) return;
        try {
            Files.deleteIfExists(s.path());
        } catch (IOException ignore) {
            // best-effort
        }
    }

    public Session get(String sessionId) {
        pruneExpired();
        return sessions.get(sessionId);
    }

    private void ensureBaseDir() throws IOException {
        if (!Files.exists(baseDir)) {
            Files.createDirectories(baseDir);
        }
    }

    private void pruneExpired() {
        Instant now = Instant.now();

        for (var it = sessions.entrySet().iterator(); it.hasNext(); ) {
            var e = it.next();
            Session s = e.getValue();

            boolean expired = s.createdAt().plus(ttl).isBefore(now);
            boolean missing = !Files.exists(s.path());

            if (expired || missing) {
                it.remove();
                try {
                    Files.deleteIfExists(s.path());
                } catch (IOException ignore) {
                    // best-effort
                }
            }
        }
    }

    private static String safeName(String s) {
        if (s == null) return "";
        String t = s.trim();
        return (t.length() > 200) ? t.substring(0, 200) : t;
    }

    public record Session(String id, Path path, Instant createdAt, String originalFilename) {}
}
