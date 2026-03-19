package dev.notegridx.security.assetvulnmanager.domain;

import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;

@Getter
@Entity
@Table(name = "cpe_vendor_aliases")
public class CpeVendorAlias {

    /**
     * Stores normalized vendor aliases that map raw vendor names
     * to canonical CPE vendor identifiers.
     */
    public static final String STATUS_ACTIVE = "ACTIVE";
    public static final String STATUS_INACTIVE = "INACTIVE";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cpe_vendor_id", nullable = false)
    private Long cpeVendorId;

    @Column(name = "alias_norm", nullable = false, length = 255)
    private String aliasNorm;

    @Column(name = "note", length = 1024)
    private String note;

    /**
     * Kept as String for compatibility with existing controller and API layers.
     */
    @Column(name = "status", nullable = false, length = 16)
    private String status = STATUS_ACTIVE;

    /**
     * Indicates how this alias was created (manual, seeded, imported, etc.).
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "source", nullable = false, length = 32)
    private AliasSource source = AliasSource.MANUAL;

    /**
     * Represents review status (manual, auto-generated, etc.).
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "review_state", nullable = false, length = 16)
    private AliasReviewState reviewState = AliasReviewState.MANUAL;

    @Column(name = "confidence")
    private Integer confidence = 0;

    @Column(name = "evidence_url", length = 1024)
    private String evidenceUrl;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected CpeVendorAlias() { }

    /**
     * Minimal constructor kept for backward-compatible creation paths.
     */
    public CpeVendorAlias(Long cpeVendorId, String aliasNorm, String note) {
        this.cpeVendorId = cpeVendorId;
        this.aliasNorm = aliasNorm;
        this.note = note;
        this.status = STATUS_ACTIVE;
        this.source = AliasSource.MANUAL;
        this.reviewState = AliasReviewState.MANUAL;
    }

    /**
     * Alternative constructor kept for compatibility with existing controller calls.
     */
    public CpeVendorAlias(String aliasNorm, Long cpeVendorId, String note) {
        this.cpeVendorId = cpeVendorId;
        this.aliasNorm = aliasNorm;
        this.note = note;
        this.status = STATUS_ACTIVE;
        this.source = AliasSource.MANUAL;
        this.reviewState = AliasReviewState.MANUAL;
    }

    /**
     * Factory for aliases created by automated seeding or suggestion workflows.
     */
    public static CpeVendorAlias seeded(
            Long cpeVendorId,
            String aliasNorm,
            String note,
            AliasSource source,
            AliasReviewState reviewState,
            Integer confidence,
            String evidenceUrl
    ) {
        CpeVendorAlias a = new CpeVendorAlias(cpeVendorId, aliasNorm, note);
        a.source = (source == null) ? AliasSource.MANUAL : source;
        a.reviewState = (reviewState == null) ? AliasReviewState.AUTO : reviewState;
        a.confidence = confidence;
        a.evidenceUrl = evidenceUrl;
        a.status = STATUS_ACTIVE;
        return a;
    }

    /**
     * Setter retained for compatibility with existing controller flows.
     */
    public void setStatus(String status) {
        if (status == null) {
            this.status = STATUS_ACTIVE;
            return;
        }
        String s = status.trim();
        this.status = s.isEmpty() ? STATUS_ACTIVE : s;
    }

    public void toggleStatus() {
        String cur = (status == null) ? "" : status.trim();
        this.status = STATUS_ACTIVE.equals(cur) ? STATUS_INACTIVE : STATUS_ACTIVE;
    }

    public void setNote(String note) { this.note = note; }
    public void setSource(AliasSource source) { if (source != null) this.source = source; }
    public void setReviewState(AliasReviewState reviewState) { if (reviewState != null) this.reviewState = reviewState; }

    public void setConfidence(Integer confidence) {
        this.confidence = (confidence == null) ? 0 : confidence;
    }

    public void setEvidenceUrl(String evidenceUrl) { this.evidenceUrl = evidenceUrl; }

    @PrePersist
    void prePersist() {
        LocalDateTime now = DbTime.now();
        this.createdAt = (this.createdAt == null) ? now : this.createdAt;
        this.updatedAt = (this.updatedAt == null) ? now : this.updatedAt;

        if (this.status == null || this.status.trim().isEmpty()) this.status = STATUS_ACTIVE;
        if (this.source == null) this.source = AliasSource.MANUAL;
        if (this.reviewState == null) this.reviewState = AliasReviewState.MANUAL;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = DbTime.now();
        if (this.status == null || this.status.trim().isEmpty()) this.status = STATUS_ACTIVE;
        if (this.source == null) this.source = AliasSource.MANUAL;
        if (this.reviewState == null) this.reviewState = AliasReviewState.MANUAL;
    }
}