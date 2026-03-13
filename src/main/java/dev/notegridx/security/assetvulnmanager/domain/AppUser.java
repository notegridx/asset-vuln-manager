package dev.notegridx.security.assetvulnmanager.domain;

import jakarta.persistence.*;
import lombok.Getter;

import java.time.LocalDateTime;

import dev.notegridx.security.assetvulnmanager.utility.DbTime;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(
        name = "app_users",
        uniqueConstraints = @UniqueConstraint(name = "uq_app_users_username", columnNames = {"username"})
)
@Getter
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String username;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked = true;

    @Column(name = "password_change_required", nullable = false)
    private boolean passwordChangeRequired = false;

    @Column(name = "bootstrap_admin", nullable = false)
    private boolean bootstrapAdmin = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "app_user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    private Set<AppRole> roles = new LinkedHashSet<>();

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected AppUser() {
    }

    public AppUser(String username, String passwordHash) {
        this.username = requireNotBlank(username, "username");
        this.passwordHash = requireNotBlank(passwordHash, "passwordHash");
        this.enabled = true;
        this.accountNonLocked = true;
        this.passwordChangeRequired = false;
        this.bootstrapAdmin = false;
    }

    public static AppUser of(String username, String passwordHash) {
        return new AppUser(username, passwordHash);
    }

    public void changePasswordHash(String passwordHash) {
        this.passwordHash = requireNotBlank(passwordHash, "passwordHash");
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public void setPasswordChangeRequired(boolean passwordChangeRequired) {
        this.passwordChangeRequired = passwordChangeRequired;
    }

    public void setBootstrapAdmin(boolean bootstrapAdmin) {
        this.bootstrapAdmin = bootstrapAdmin;
    }

    public void replaceRoles(Set<AppRole> roles) {
        this.roles.clear();
        if (roles != null) {
            this.roles.addAll(roles);
        }
    }

    public void addRole(AppRole role) {
        if (role != null) this.roles.add(role);
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
