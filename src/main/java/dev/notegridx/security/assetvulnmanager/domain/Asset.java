package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

import lombok.Getter;

@Entity
@Table(
        name = "assets",
uniqueConstraints = @UniqueConstraint(
        name = "uq_assets_external_key",
        columnNames = {"external_key"}
))
@Getter
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "external_key", length = 128)
    private String externalKey;

    @NotBlank
    @Column(nullable = false)
    private String name;

    @Column(name = "asset_type")
    private String assetType;

    private String owner;

    @Lob
    private String note;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @OneToMany(mappedBy = "asset", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SoftwareInstall> softwareInstalls = new ArrayList<>();

    protected Asset() {
    }

    public Asset(String name) {
        this.name = name;
    }

    public void updateDetails(String externalKey, String assetType, String owner, String note) {
        this.externalKey = normalizeNullable(externalKey);
        this.assetType = assetType;
        this.owner = owner;
        this.note = note;
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }


}
