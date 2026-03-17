package dev.notegridx.security.assetvulnmanager.domain;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Getter;

import java.time.LocalDateTime;

@Entity
@Table(name = "system_settings")
@Getter
public class SystemSetting {

    @Id
    @Column(name = "setting_key", nullable = false, length = 128)
    private String settingKey;

    @Column(name = "setting_value", nullable = false, length = 2048)
    private String settingValue;

    @Column(name = "updated_by", length = 100)
    private String updatedBy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected SystemSetting() {
    }

    public SystemSetting(String settingKey, String settingValue, String updatedBy) {
        this.settingKey = requireKey(settingKey);
        this.settingValue = normalizeValue(settingValue);
        this.updatedBy = normalizeNullable(updatedBy);
    }

    public static SystemSetting of(String settingKey, String settingValue, String updatedBy) {
        return new SystemSetting(settingKey, settingValue, updatedBy);
    }

    public void updateValue(String settingValue, String updatedBy) {
        this.settingValue = normalizeValue(settingValue);
        this.updatedBy = normalizeNullable(updatedBy);
    }

    private static String requireKey(String s) {
        if (s == null || s.trim().isEmpty()) {
            throw new IllegalArgumentException("settingKey is required");
        }
        return s.trim();
    }

    private static String normalizeValue(String s) {
        if (s == null) return "";
        return s.trim();
    }

    private static String normalizeNullable(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = DbTime.now();
        if (createdAt == null) createdAt = now;
        if (updatedAt == null) updatedAt = now;
        if (settingValue == null) settingValue = "";
    }

    @PreUpdate
    void preUpdate() {
        updatedAt = DbTime.now();
        if (settingValue == null) settingValue = "";
    }
}