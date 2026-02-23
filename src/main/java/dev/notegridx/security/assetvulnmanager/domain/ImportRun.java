package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Table(name = "import_runs")
@Getter
public class ImportRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String source;

    @Column(nullable = false)
    private String kind;

    @Column(nullable = false)
    private LocalDateTime startedAt;

    private LocalDateTime finishedAt;

    private String fileHash;

    @Lob
    private String summary;

    @Column(nullable = false)
    private int assetsUpserted = 0;

    @Column(nullable = false)
    private int softwareUpserted = 0;

    @Column(nullable = false)
    private int unresolvedCount = 0;

    @Column(nullable = false)
    private int errorCount = 0;

    @Column(nullable = false, name = "created_at")
    private LocalDateTime createdAt;

    protected ImportRun() {
    }

    public static ImportRun start(String source, String kind) {
        ImportRun run = new ImportRun();
        run.source = source;
        run.kind = kind;
        run.startedAt = LocalDateTime.now();
        run.assetsUpserted = 0;
        run.softwareUpserted = 0;
        run.unresolvedCount = 0;
        run.errorCount = 0;
        return run;
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (this.startedAt == null) this.startedAt = now;
        if (this.createdAt == null) this.createdAt = now;
        if (this.source == null || this.source.trim().isEmpty()) this.source = "MANUAL";
    }

    // ---- setters（CsvImportService が使う分だけ）----

    public void setSource(String source) {
        this.source = source;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public void setStartedAt(LocalDateTime startedAt) {
        this.startedAt = startedAt;
    }

    public void setFinishedAt(LocalDateTime finishedAt) {
        this.finishedAt = finishedAt;
    }

    public void setFileHash(String fileHash) {
        this.fileHash = fileHash;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public void setAssetsUpserted(int assetsUpserted) {
        this.assetsUpserted = assetsUpserted;
    }

    public void setSoftwareUpserted(int softwareUpserted) {
        this.softwareUpserted = softwareUpserted;
    }

    public void setUnresolvedCount(int unresolvedCount) {
        this.unresolvedCount = unresolvedCount;
    }

    public void setErrorCount(int errorCount) {
        this.errorCount = errorCount;
    }
}