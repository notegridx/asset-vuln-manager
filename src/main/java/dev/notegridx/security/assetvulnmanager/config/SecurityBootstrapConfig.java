package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
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
            PasswordEncoder passwordEncoder
    ) {
        return args -> {
            if (appUserRepository.existsByUsername("admin")) {
                return;
            }

            List<AppRole> roles = appRoleRepository.findByRoleNameIn(List.of("ADMIN"));
            if (roles.isEmpty()) {
                AppRole adminRole = appRoleRepository.save(AppRole.of("ADMIN"));
                roles = List.of(adminRole);
            }

            AppUser admin = AppUser.of("admin", passwordEncoder.encode("admin123!"));
            admin.replaceRoles(new LinkedHashSet<>(roles));
            appUserRepository.save(admin);
        };
    }
}