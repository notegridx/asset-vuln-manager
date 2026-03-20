package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.LinkedHashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityLoginIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private AppRoleRepository appRoleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private SecurityAuditService securityAuditService;

    @BeforeEach
    void setUp() {
        appUserRepository.deleteAll();

        // app_roles is expected to be seeded by MERGE statements in schema-h2.sql.
        // Backfill defensively when the test database was initialized without them.
        ensureRoleExists("ADMIN");
        ensureRoleExists("OPERATOR");
        ensureRoleExists("VIEWER");
    }

    @Test
    @DisplayName("failed login increments failedLoginCount and keeps account unlocked before threshold")
    void loginFailure_incrementsCounter_beforeThreshold() throws Exception {
        createUser("alice", "correct-password", false);

        mockMvc.perform(formLogin().user("alice").password("wrong-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error&reason=bad-credentials"));

        AppUser reloaded = appUserRepository.findByUsername("alice").orElseThrow();

        assertThat(reloaded.getFailedLoginCount()).isEqualTo(1);
        assertThat(reloaded.isAccountNonLocked()).isTrue();
        assertThat(reloaded.getLastFailedLoginAt()).isNotNull();
        assertThat(reloaded.getLockedAt()).isNull();

        verify(securityAuditService, atLeastOnce()).log(
                eq("LOGIN_FAILURE"),
                eq("alice"),
                eq("alice"),
                eq("FAILURE"),
                any(),
                eq("Login failed. failedLoginCount=1")
        );
    }

    @Test
    @DisplayName("failed login locks account when threshold is reached")
    void loginFailure_locksAccount_atThreshold() throws Exception {
        AppUser user = createUser("alice", "correct-password", false);

        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();
        appUserRepository.save(user);

        mockMvc.perform(formLogin().user("alice").password("wrong-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error&reason=locked"));

        AppUser reloaded = appUserRepository.findByUsername("alice").orElseThrow();

        assertThat(reloaded.getFailedLoginCount()).isEqualTo(5);
        assertThat(reloaded.isAccountNonLocked()).isFalse();
        assertThat(reloaded.getLockedAt()).isNotNull();
        assertThat(reloaded.getLastFailedLoginAt()).isNotNull();

        verify(securityAuditService, atLeastOnce()).log(
                eq("LOGIN_FAILURE"),
                eq("alice"),
                eq("alice"),
                eq("FAILURE"),
                any(),
                eq("Login failed. failedLoginCount=5")
        );
        verify(securityAuditService, atLeastOnce()).log(
                eq("ACCOUNT_LOCKED"),
                eq("system"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("Account locked after too many failed login attempts.")
        );
    }

    @Test
    @DisplayName("successful login clears previous failure counters")
    void loginSuccess_clearsFailureCounters() throws Exception {
        AppUser user = createUser("alice", "correct-password", false);

        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();
        appUserRepository.save(user);

        mockMvc.perform(formLogin().user("alice").password("correct-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));

        AppUser reloaded = appUserRepository.findByUsername("alice").orElseThrow();

        assertThat(reloaded.getFailedLoginCount()).isEqualTo(0);
        assertThat(reloaded.getLastFailedLoginAt()).isNull();
        assertThat(reloaded.isAccountNonLocked()).isTrue();
        assertThat(reloaded.getLockedAt()).isNull();

        verify(securityAuditService, atLeastOnce()).log(
                eq("LOGIN_SUCCESS"),
                eq("alice"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("Login succeeded.")
        );
    }

    @Test
    @DisplayName("successful login redirects to change-password when passwordChangeRequired is true")
    void loginSuccess_redirectsToChangePassword_whenRequired() throws Exception {
        createUser("alice", "correct-password", true);

        mockMvc.perform(formLogin().user("alice").password("correct-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"));

        AppUser reloaded = appUserRepository.findByUsername("alice").orElseThrow();

        assertThat(reloaded.getFailedLoginCount()).isEqualTo(0);
        assertThat(reloaded.getLastFailedLoginAt()).isNull();

        verify(securityAuditService, atLeastOnce()).log(
                eq("LOGIN_SUCCESS"),
                eq("alice"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("Login succeeded.")
        );
    }

    @Test
    @DisplayName("locked account cannot log in even with correct password")
    void lockedAccount_cannotLogin() throws Exception {
        AppUser user = createUser("alice", "correct-password", false);
        user.lockNow();
        appUserRepository.save(user);

        mockMvc.perform(formLogin().user("alice").password("correct-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?error&reason=locked"));

        AppUser reloaded = appUserRepository.findByUsername("alice").orElseThrow();

        assertThat(reloaded.isAccountNonLocked()).isFalse();
        assertThat(reloaded.getLockedAt()).isNotNull();
    }

    private AppUser createUser(String username, String rawPassword, boolean passwordChangeRequired) {
        AppRole adminRole = appRoleRepository.findByRoleNameIn(List.of("ADMIN"))
                .stream()
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("ADMIN role not found"));

        AppUser user = AppUser.of(username, passwordEncoder.encode(rawPassword));
        user.setEnabled(true);
        user.setAccountNonLocked(true);
        user.setPasswordChangeRequired(passwordChangeRequired);
        user.setBootstrapAdmin(false);
        user.replaceRoles(new LinkedHashSet<>(List.of(adminRole)));

        return appUserRepository.save(user);
    }

    private void ensureRoleExists(String roleName) {
        boolean exists = appRoleRepository.findByRoleNameIn(List.of(roleName))
                .stream()
                .anyMatch(r -> roleName.equals(r.getRoleName()));

        if (!exists) {
            appRoleRepository.save(AppRole.of(roleName));
        }
    }
}