package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;

@Entity
@Table(
        name = "app_roles",
        uniqueConstraints = @UniqueConstraint(name = "uq_app_roles_name", columnNames = {"role_name"})
)
@Getter
public class AppRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "role_name", nullable = false, length = 50)
    private String roleName;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected AppRole() {
    }

    public AppRole(String roleName) {
        this.roleName = requireNotBlank(roleName, "roleName");
    }

    public static AppRole of(String roleName) {
        return new AppRole(roleName);
    }

    private static String requireNotBlank(String s, String field) {
        if (s == null || s.trim().isEmpty()) throw new IllegalArgumentException(field + " is required");
        return s.trim();
    }

    @PrePersist
    void prePersist() {
        LocalDateTime now = DbTime.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void preUpdate() {
        this.updatedAt = DbTime.now();
    }
}