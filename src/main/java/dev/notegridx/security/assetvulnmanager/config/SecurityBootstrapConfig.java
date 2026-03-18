package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.LinkedHashSet;
import java.util.List;

@Configuration
public class SecurityBootstrapConfig {

    @Bean
    CommandLineRunner seedDefaultAdmin(
            AppUserRepository appUserRepository,
            AppRoleRepository appRoleRepository,
            PasswordEncoder passwordEncoder,
            SecurityAuditService securityAuditService,
            @Value("${app.security.bootstrap-admin.enabled:false}") boolean bootstrapAdminEnabled,
            @Value("${app.security.bootstrap-admin.username:admin}") String bootstrapAdminUsername,
            @Value("${app.security.bootstrap-admin.password:}") String bootstrapAdminPassword
    ) {
        return args -> {
            if (!bootstrapAdminEnabled) {
                return;
            }

            String username = safe(bootstrapAdminUsername);
            String password = safe(bootstrapAdminPassword);

            if (username == null || password == null) {
                throw new IllegalStateException(
                        "Bootstrap admin is enabled, but username/password is missing. " +
                                "Set app.security.bootstrap-admin.username and password (or AVM_BOOTSTRAP_ADMIN_PASSWORD)."
                );
            }

            if (appUserRepository.existsByUsername(username)) {
                return;
            }

            List<AppRole> roles = appRoleRepository.findByRoleNameIn(List.of("ADMIN"));
            if (roles.isEmpty()) {
                AppRole adminRole = appRoleRepository.save(AppRole.of("ADMIN"));
                roles = List.of(adminRole);
            }

            AppUser admin = AppUser.of(username, passwordEncoder.encode(password));
            admin.replaceRoles(new LinkedHashSet<>(roles));
            admin.setPasswordChangeRequired(true);
            admin.setBootstrapAdmin(true);
            admin.setEnabled(true);
            admin.setAccountNonLocked(true);
            admin.unlock();

            appUserRepository.save(admin);

            securityAuditService.log(
                    "BOOTSTRAP_ADMIN_CREATED",
                    "system",
                    username,
                    "SUCCESS",
                    null,
                    "Bootstrap admin account was created."
            );
        };
    }

    private static String safe(String s) {
        if (s == null) {
            return null;
        }
        String v = s.trim();
        return v.isEmpty() ? null : v;
    }
}