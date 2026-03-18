package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@WebMvcTest(controllers = AdminUsersController.class)
@ActiveProfiles("mysqltest")
@Import(AdminUsersControllerWebMvcTest.MethodSecurityTestConfig.class)
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminUsersControllerWebMvcTest {

    @TestConfiguration
    @EnableMethodSecurity
    static class MethodSecurityTestConfig {
    }

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AppUserRepository appUserRepository;

    @MockitoBean
    private AppRoleRepository appRoleRepository;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private SecurityAuditService securityAuditService;

    @Test
    @DisplayName("GET /admin/users returns users page")
    void list_returnsUsersPage() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole operatorRole = role("OPERATOR");

        AppUser admin = AppUser.of("admin", "hash");
        admin.replaceRoles(Set.of(adminRole));

        when(appUserRepository.findAll()).thenReturn(List.of(admin));
        when(appRoleRepository.findAllByOrderByRoleNameAsc()).thenReturn(List.of(adminRole, operatorRole));

        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/users"))
                .andExpect(model().attributeExists("users"))
                .andExpect(model().attributeExists("roles"));
    }

    @Test
    @DisplayName("GET /admin/users is forbidden for non-admin")
    @WithMockUser(username = "viewer", roles = "VIEWER")
    void list_forbidden_forNonAdmin() throws Exception {
        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /admin/users creates user")
    void create_ok() throws Exception {
        AppRole userRole = role("OPERATOR");

        when(appUserRepository.existsByUsername("bob")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of("OPERATOR"))).thenReturn(List.of(userRole));
        when(passwordEncoder.encode("secret123")).thenReturn("ENC(secret123)");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> {
            AppUser saved = inv.getArgument(0);
            setId(saved, 101L);
            return saved;
        });

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "bob")
                        .param("password", "secret123")
                        .param("roles", "OPERATOR"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User created."))
                .andExpect(jsonPath("$.id").value(101))
                .andExpect(jsonPath("$.username").value("bob"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.roles[0]").value("OPERATOR"));

        verify(passwordEncoder).encode("secret123");
        verify(appUserRepository).save(argThat(u ->
                "bob".equals(u.getUsername())
                        && !u.isEnabled()
                        && u.isAccountNonLocked()
                        && !u.isPasswordChangeRequired()
                        && !u.isBootstrapAdmin()
                        && u.getFailedLoginCount() == 0
                        && u.getRoles().size() == 1
                        && hasRole(u, "OPERATOR")
        ));
        verify(securityAuditService).log(
                eq("USER_CREATED"),
                eq("admin"),
                eq("bob"),
                eq("SUCCESS"),
                any(),
                eq("User created.")
        );
    }

    @Test
    @DisplayName("POST /admin/users creates enabled user when enabled flag is true")
    void create_enabledTrue_ok() throws Exception {
        AppRole adminRole = role("ADMIN");

        when(appUserRepository.existsByUsername("alice")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of("ADMIN"))).thenReturn(List.of(adminRole));
        when(passwordEncoder.encode("secret123")).thenReturn("ENC(secret123)");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> {
            AppUser saved = inv.getArgument(0);
            setId(saved, 102L);
            return saved;
        });

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123")
                        .param("roles", "ADMIN")
                        .param("enabled", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User created."))
                .andExpect(jsonPath("$.id").value(102))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.roles[0]").value("ADMIN"));

        verify(appUserRepository).save(argThat(AppUser::isEnabled));
    }

    @Test
    @DisplayName("POST /admin/users rejects blank username")
    void create_blankUsername_rejects() throws Exception {
        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "   ")
                        .param("password", "secret123")
                        .param("roles", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("Username is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(passwordEncoder, never()).encode(any());
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/users rejects blank password")
    void create_blankPassword_rejects() throws Exception {
        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "   ")
                        .param("roles", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("Password is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(passwordEncoder, never()).encode(any());
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/users rejects duplicate username")
    void create_duplicateUsername_rejects() throws Exception {
        when(appUserRepository.existsByUsername("alice")).thenReturn(true);

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123")
                        .param("roles", "ADMIN"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("Username already exists: alice"));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/users rejects empty roles")
    void create_noRoles_rejects() throws Exception {
        when(appUserRepository.existsByUsername("alice")).thenReturn(false);

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("At least one role is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/users/{id}/enable updates user")
    void enable_updatesUser() throws Exception {
        AppRole userRole = role("OPERATOR");
        AppUser user = AppUser.of("alice", "hash");
        user.setEnabled(false);
        user.replaceRoles(Set.of(userRole));
        setId(user, 10L);

        when(appUserRepository.findById(10L)).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/10/enable").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User enabled."))
                .andExpect(jsonPath("$.id").value(10))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.roles[0]").value("OPERATOR"));

        verify(appUserRepository).save(argThat(AppUser::isEnabled));
        verify(securityAuditService).log(
                eq("USER_ENABLED"),
                eq("admin"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("User enabled.")
        );
    }

    @Test
    @DisplayName("POST /admin/users/{id}/disable updates user")
    void disable_updatesUser() throws Exception {
        AppRole userRole = role("OPERATOR");
        AppUser user = AppUser.of("alice", "hash");
        user.setEnabled(true);
        user.replaceRoles(Set.of(userRole));
        setId(user, 11L);

        when(appUserRepository.findById(11L)).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/11/disable").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User disabled."))
                .andExpect(jsonPath("$.id").value(11))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.roles[0]").value("OPERATOR"));

        verify(appUserRepository).save(argThat(u -> !u.isEnabled()));
        verify(securityAuditService).log(
                eq("USER_DISABLED"),
                eq("admin"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("User disabled.")
        );
    }

    @Test
    @DisplayName("POST /admin/users/{id}/disable rejects self-disable")
    void disable_self_rejects() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppUser user = AppUser.of("admin", "hash");
        user.setEnabled(true);
        user.replaceRoles(Set.of(adminRole));
        setId(user, 12L);

        when(appUserRepository.findById(12L)).thenReturn(Optional.of(user));

        mockMvc.perform(post("/admin/users/12/disable").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("You cannot disable your own account."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/users/{id}/unlock unlocks user and resets counters")
    void unlock_updatesUser() throws Exception {
        AppRole userRole = role("OPERATOR");
        AppUser user = AppUser.of("alice", "hash");
        user.setEnabled(true);
        user.setAccountNonLocked(false);
        user.replaceRoles(Set.of(userRole));
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();
        user.lockNow();
        setId(user, 13L);

        when(appUserRepository.findById(13L)).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/13/unlock").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User unlocked."))
                .andExpect(jsonPath("$.id").value(13))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.roles[0]").value("OPERATOR"));

        verify(appUserRepository).save(argThat(u ->
                u.isAccountNonLocked()
                        && u.getFailedLoginCount() == 0
                        && u.getLockedAt() == null
                        && u.getLastFailedLoginAt() == null
        ));
        verify(securityAuditService).log(
                eq("USER_UNLOCKED"),
                eq("admin"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("User unlocked and failed login counter reset.")
        );
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles updates roles")
    void updateRoles_updatesUserRoles() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole operatorRole = role("OPERATOR");

        AppUser user = AppUser.of("alice", "hash");
        user.setEnabled(false);
        user.replaceRoles(Set.of(operatorRole));
        setId(user, 20L);

        when(appUserRepository.findById(20L)).thenReturn(Optional.of(user));
        when(appRoleRepository.findByRoleNameIn(List.of("ADMIN", "OPERATOR")))
                .thenReturn(List.of(adminRole, operatorRole));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/20/roles")
                        .with(csrf())
                        .param("roles", "ADMIN", "OPERATOR"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("Roles updated."))
                .andExpect(jsonPath("$.id").value(20))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.roles[0]").value("ADMIN"))
                .andExpect(jsonPath("$.roles[1]").value("OPERATOR"));

        verify(appUserRepository).save(argThat(u ->
                u.getRoles().size() == 2
                        && hasRole(u, "ADMIN")
                        && hasRole(u, "OPERATOR")
        ));
        verify(securityAuditService).log(
                eq("USER_ROLES_UPDATED"),
                eq("admin"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("Roles updated to: [ADMIN, OPERATOR]")
        );
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles rejects empty roles")
    void updateRoles_empty_rejects() throws Exception {
        AppUser user = AppUser.of("alice", "hash");
        setId(user, 21L);

        when(appUserRepository.findById(21L)).thenReturn(Optional.of(user));

        mockMvc.perform(post("/admin/users/21/roles").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("At least one role is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles rejects removing ADMIN from self")
    void updateRoles_selfRemoveAdmin_rejects() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole operatorRole = role("OPERATOR");

        AppUser user = AppUser.of("admin", "hash");
        user.replaceRoles(Set.of(adminRole));
        setId(user, 22L);

        when(appUserRepository.findById(22L)).thenReturn(Optional.of(user));
        when(appRoleRepository.findByRoleNameIn(List.of("OPERATOR")))
                .thenReturn(List.of(operatorRole));

        mockMvc.perform(post("/admin/users/22/roles")
                        .with(csrf())
                        .param("roles", "OPERATOR"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.message").value("You cannot remove ADMIN from your own account."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    private static AppRole role(String roleName) {
        return AppRole.of(roleName);
    }

    private static boolean hasRole(AppUser user, String roleName) {
        return user.getRoles().stream().anyMatch(r -> roleName.equals(r.getRoleName()));
    }

    private static void setId(Object target, Long value) throws Exception {
        Field field = findField(target.getClass(), "id");
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }
}