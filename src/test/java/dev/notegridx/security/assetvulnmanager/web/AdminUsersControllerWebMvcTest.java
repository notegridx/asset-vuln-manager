package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
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

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
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
@ActiveProfiles("test")
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

    @Test
    @DisplayName("GET /admin/users returns users page")
    void list_returnsUsersPage() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole userRole = role("USER");

        AppUser admin = AppUser.of("admin", "hash");
        admin.replaceRoles(Set.of(adminRole));

        when(appUserRepository.findAll()).thenReturn(List.of(admin));
        when(appRoleRepository.findAllByOrderByRoleNameAsc()).thenReturn(List.of(adminRole, userRole));

        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/users"))
                .andExpect(model().attributeExists("users"))
                .andExpect(model().attributeExists("roles"));
    }

    @Test
    @DisplayName("GET /admin/users is forbidden for non-admin")
    @WithMockUser(username = "user", roles = "USER")
    void list_forbidden_forNonAdmin() throws Exception {
        mockMvc.perform(get("/admin/users"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /admin/users creates user and returns JSON")
    void create_valid_redirects() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole userRole = role("USER");

        when(appUserRepository.existsByUsername("alice")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of("ADMIN", "USER")))
                .thenReturn(List.of(adminRole, userRole));
        when(passwordEncoder.encode("secret123")).thenReturn("ENC(secret123)");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> {
            AppUser u = inv.getArgument(0);
            setId(u, 100L);
            return u;
        });

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123")
                        .param("roles", "ADMIN", "USER")
                        .param("enabled", "true"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User created: alice"))
                .andExpect(jsonPath("$.id").value(100))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.roles", hasSize(2)))
                .andExpect(jsonPath("$.roles", containsInAnyOrder("ADMIN", "USER")));

        verify(appUserRepository).save(argThat(u ->
                "alice".equals(u.getUsername())
                        && u.isEnabled()
                        && u.isAccountNonLocked()
                        && !u.isPasswordChangeRequired()
                        && !u.isBootstrapAdmin()
                        && u.getRoles().size() == 2
                        && hasRole(u, "ADMIN")
                        && hasRole(u, "USER")
        ));
    }

    @Test
    @DisplayName("POST /admin/users creates non-bootstrap user without forced password change")
    void create_valid_defaultsSecurityFlagsToFalse() throws Exception {
        AppRole userRole = role("USER");

        when(appUserRepository.existsByUsername("bob")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of("USER")))
                .thenReturn(List.of(userRole));
        when(passwordEncoder.encode("pw12345")).thenReturn("ENC(pw12345)");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> {
            AppUser u = inv.getArgument(0);
            setId(u, 101L);
            return u;
        });

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "bob")
                        .param("password", "pw12345")
                        .param("roles", "USER"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("User created: bob"))
                .andExpect(jsonPath("$.id").value(101))
                .andExpect(jsonPath("$.username").value("bob"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.roles", hasSize(1)))
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        verify(appUserRepository).save(argThat(u ->
                "bob".equals(u.getUsername())
                        && !u.isEnabled()
                        && u.isAccountNonLocked()
                        && !u.isPasswordChangeRequired()
                        && !u.isBootstrapAdmin()
                        && u.getRoles().size() == 1
                        && hasRole(u, "USER")
        ));
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
                .andExpect(jsonPath("$.error").value("Username is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(passwordEncoder, never()).encode(any());
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
                .andExpect(jsonPath("$.error").value("Password is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(passwordEncoder, never()).encode(any());
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
                .andExpect(jsonPath("$.error").value("Username already exists: alice"));

        verify(appUserRepository, never()).save(any(AppUser.class));
    }

    @Test
    @DisplayName("POST /admin/users rejects empty roles")
    void create_noRoles_rejects() throws Exception {
        when(appUserRepository.existsByUsername("alice")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of())).thenReturn(List.of());

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.error").value("At least one role is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/enable updates user")
    void enable_updatesUser() throws Exception {
        AppRole userRole = role("USER");
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
                .andExpect(jsonPath("$.message").value("User enabled: alice"))
                .andExpect(jsonPath("$.id").value(10))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.roles", hasSize(1)))
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        verify(appUserRepository).save(argThat(AppUser::isEnabled));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/disable updates user")
    void disable_updatesUser() throws Exception {
        AppRole userRole = role("USER");
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
                .andExpect(jsonPath("$.message").value("User disabled: alice"))
                .andExpect(jsonPath("$.id").value(11))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.enabled").value(false))
                .andExpect(jsonPath("$.roles", hasSize(1)))
                .andExpect(jsonPath("$.roles[0]").value("USER"));

        verify(appUserRepository).save(argThat(u -> !u.isEnabled()));
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
                .andExpect(jsonPath("$.error").value("You cannot disable your own account."));

        verify(appUserRepository, never()).save(any(AppUser.class));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles updates roles")
    void updateRoles_updatesUserRoles() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole userRole = role("USER");

        AppUser user = AppUser.of("alice", "hash");
        user.replaceRoles(Set.of(userRole));
        setId(user, 20L);

        when(appUserRepository.findById(20L)).thenReturn(Optional.of(user));
        when(appRoleRepository.findByRoleNameIn(List.of("ADMIN", "USER")))
                .thenReturn(List.of(adminRole, userRole));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/20/roles")
                        .with(csrf())
                        .param("roles", "ADMIN", "USER"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(true))
                .andExpect(jsonPath("$.message").value("Roles updated: alice"))
                .andExpect(jsonPath("$.id").value(20))
                .andExpect(jsonPath("$.username").value("alice"))
                .andExpect(jsonPath("$.roles", hasSize(2)))
                .andExpect(jsonPath("$.roles", containsInAnyOrder("ADMIN", "USER")));

        verify(appUserRepository).save(argThat(u ->
                u.getRoles().size() == 2
                        && hasRole(u, "ADMIN")
                        && hasRole(u, "USER")
        ));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles rejects empty roles")
    void updateRoles_empty_rejects() throws Exception {
        AppUser user = AppUser.of("alice", "hash");
        setId(user, 21L);

        when(appUserRepository.findById(21L)).thenReturn(Optional.of(user));
        when(appRoleRepository.findByRoleNameIn(List.of())).thenReturn(List.of());

        mockMvc.perform(post("/admin/users/21/roles").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.error").value("At least one role is required."));

        verify(appUserRepository, never()).save(any(AppUser.class));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles rejects self ADMIN removal")
    void updateRoles_selfAdminRemoval_rejects() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppUser user = AppUser.of("admin", "hash");
        user.replaceRoles(Set.of(adminRole));
        setId(user, 22L);

        when(appUserRepository.findById(22L)).thenReturn(Optional.of(user));
        when(appRoleRepository.findByRoleNameIn(List.of("USER")))
                .thenReturn(List.of(role("USER")));

        mockMvc.perform(post("/admin/users/22/roles")
                        .with(csrf())
                        .param("roles", "USER"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.ok").value(false))
                .andExpect(jsonPath("$.error").value("You cannot remove ADMIN from your own account."));

        verify(appUserRepository, never()).save(any(AppUser.class));
    }

    private static AppRole role(String name) {
        AppRole r = AppRole.of(name);
        setId(r, name.equals("ADMIN") ? 1L : 2L);
        return r;
    }

    private static boolean hasRole(AppUser user, String roleName) {
        return user.getRoles().stream()
                .map(AppRole::getRoleName)
                .anyMatch(roleName::equals);
    }

    private static void setId(Object target, Long id) {
        try {
            var field = findField(target.getClass(), "id");
            if (field == null) {
                throw new NoSuchFieldException("id");
            }
            field.setAccessible(true);
            field.set(target, id);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set id via reflection", e);
        }
    }

    private static java.lang.reflect.Field findField(Class<?> type, String name) {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        return null;
    }
}