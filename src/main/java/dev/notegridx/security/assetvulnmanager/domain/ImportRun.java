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

    // ===== Added for staged JSON import (must match schema.sql columns) =====

    @Column(nullable = false, length = 16)
    private String status = "IMPORTED"; // default to keep legacy inserts safe

    @Column(name = "original_filename", length = 255)
    private String originalFilename;

    @Column(length = 128)
    private String sha256;

    @Column(name = "total_rows", nullable = false)
    private int totalRows = 0;

    @Column(name = "valid_rows", nullable = false)
    private int validRows = 0;

    @Column(name = "invalid_rows", nullable = false)
    private int invalidRows = 0;

    @Column(name = "error_message", length = 1024)
    private String errorMessage;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected ImportRun() {
    }

    // 既存互換：CSV等が使う start は残す
    public static ImportRun start(String source, String kind) {
        ImportRun run = new ImportRun();
        run.source = source;
        run.kind = kind;
        run.startedAt = LocalDateTime.now();
        run.assetsUpserted = 0;
        run.softwareUpserted = 0;
        run.unresolvedCount = 0;
        run.errorCount = 0;

        // legacy-safe defaults
        run.status = "IMPORTED";
        run.totalRows = 0;
        run.validRows = 0;
        run.invalidRows = 0;
        return run;
    }

    // 新規：staging用途（Upload→Preview→Import）
    public static ImportRun newStaged(String source, String kind, String originalFilename, String sha256) {
        ImportRun run = ImportRun.start(source, kind);
        run.status = "STAGED";
        run.originalFilename = originalFilename;
        run.sha256 = sha256;
        return run;
    }

    public void markCounts(int totalRows, int validRows, int invalidRows) {
        this.totalRows = totalRows;
        this.validRows = validRows;
        this.invalidRows = invalidRows;
    }

    public void markImported(int assetsUpserted, int softwareUpserted, String summary) {
        this.assetsUpserted = assetsUpserted;
        this.softwareUpserted = softwareUpserted;
        this.summary = summary;
        this.status = "IMPORTED";
        this.finishedAt = LocalDateTime.now();
    }

    public void markFailed(String errorMessage) {
        this.status = "FAILED";
        this.errorMessage = errorMessage;
        this.finishedAt = LocalDateTime.now();
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();

        if (this.startedAt == null) this.startedAt = now;
        if (this.createdAt == null) this.createdAt = now;
        if (this.updatedAt == null) this.updatedAt = now;

        if (this.source == null || this.source.trim().isEmpty()) this.source = "MANUAL";
        if (this.status == null || this.status.trim().isEmpty()) this.status = "IMPORTED";
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
        if (this.status == null || this.status.trim().isEmpty()) this.status = "IMPORTED";
    }

    // ---- setters（CsvImportService が使う分だけ）----

    public void setSource(String source) { this.source = source; }
    public void setKind(String kind) { this.kind = kind; }
    public void setStartedAt(LocalDateTime startedAt) { this.startedAt = startedAt; }
    public void setFinishedAt(LocalDateTime finishedAt) { this.finishedAt = finishedAt; }
    public void setFileHash(String fileHash) { this.fileHash = fileHash; }
    public void setSummary(String summary) { this.summary = summary; }
    public void setAssetsUpserted(int assetsUpserted) { this.assetsUpserted = assetsUpserted; }
    public void setSoftwareUpserted(int softwareUpserted) { this.softwareUpserted = softwareUpserted; }
    public void setUnresolvedCount(int unresolvedCount) { this.unresolvedCount = unresolvedCount; }
    public void setErrorCount(int errorCount) { this.errorCount = errorCount; }

    // (optional) setters for staged fields if you need them elsewhere
    public void setStatus(String status) { this.status = status; }
    public void setOriginalFilename(String originalFilename) { this.originalFilename = originalFilename; }
    public void setSha256(String sha256) { this.sha256 = sha256; }
    public void setTotalRows(int totalRows) { this.totalRows = totalRows; }
    public void setValidRows(int validRows) { this.validRows = validRows; }
    public void setInvalidRows(int invalidRows) { this.invalidRows = invalidRows; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}