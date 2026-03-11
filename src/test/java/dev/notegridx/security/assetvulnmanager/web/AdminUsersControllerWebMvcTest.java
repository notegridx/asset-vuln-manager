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
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
    @DisplayName("POST /admin/users creates user and redirects")
    void create_valid_redirects() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole userRole = role("USER");

        when(appUserRepository.existsByUsername("alice")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of("ADMIN", "USER")))
                .thenReturn(List.of(adminRole, userRole));
        when(passwordEncoder.encode("secret123")).thenReturn("ENC(secret123)");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123")
                        .param("roles", "ADMIN", "USER")
                        .param("enabled", "true"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("message", "User created: alice"));

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
        when(passwordEncoder.encode("secret123")).thenReturn("ENC(secret123)");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "bob")
                        .param("password", "secret123")
                        .param("roles", "USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("message", "User created: bob"));

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
                        .param("roles", "USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "Username is required."));

        verify(appUserRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    @DisplayName("POST /admin/users rejects blank password")
    void create_blankPassword_rejects() throws Exception {
        when(appUserRepository.existsByUsername("alice")).thenReturn(false);

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "   ")
                        .param("roles", "USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "Password is required."));

        verify(appUserRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(any());
    }

    @Test
    @DisplayName("POST /admin/users rejects duplicate username")
    void create_duplicateUsername_rejects() throws Exception {
        when(appUserRepository.existsByUsername("admin")).thenReturn(true);

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "admin")
                        .param("password", "secret123")
                        .param("roles", "USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "Username already exists: admin"));

        verify(appUserRepository, never()).save(any());
    }

    @Test
    @DisplayName("POST /admin/users rejects when no roles selected")
    void create_noRoles_rejects() throws Exception {
        when(appUserRepository.existsByUsername("alice")).thenReturn(false);
        when(appRoleRepository.findByRoleNameIn(List.of())).thenReturn(List.of());

        mockMvc.perform(post("/admin/users")
                        .with(csrf())
                        .param("username", "alice")
                        .param("password", "secret123"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "At least one role is required."));

        verify(appUserRepository, never()).save(any());
    }

    @Test
    @DisplayName("POST /admin/users/{id}/enable enables user")
    void enable_updatesUser() throws Exception {
        AppUser bob = AppUser.of("bob", "hash");
        bob.setEnabled(false);

        when(appUserRepository.findById(10L)).thenReturn(Optional.of(bob));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/10/enable")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("message", "User enabled: bob"));

        verify(appUserRepository).save(argThat(AppUser::isEnabled));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/disable disables user")
    void disable_updatesUser() throws Exception {
        AppUser bob = AppUser.of("bob", "hash");
        bob.setEnabled(true);

        when(appUserRepository.findById(11L)).thenReturn(Optional.of(bob));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/11/disable")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("message", "User disabled: bob"));

        verify(appUserRepository).save(argThat(u -> !u.isEnabled()));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/disable rejects self-disable")
    void disable_self_rejects() throws Exception {
        AppUser admin = AppUser.of("admin", "hash");
        admin.setEnabled(true);

        when(appUserRepository.findById(1L)).thenReturn(Optional.of(admin));

        mockMvc.perform(post("/admin/users/1/disable")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "You cannot disable your own account."));

        verify(appUserRepository, never()).save(any());
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles updates roles")
    void updateRoles_updatesUserRoles() throws Exception {
        AppRole adminRole = role("ADMIN");
        AppRole userRole = role("USER");

        AppUser bob = AppUser.of("bob", "hash");
        bob.replaceRoles(Set.of(userRole));

        when(appUserRepository.findById(20L)).thenReturn(Optional.of(bob));
        when(appRoleRepository.findByRoleNameIn(List.of("ADMIN", "USER")))
                .thenReturn(List.of(adminRole, userRole));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/users/20/roles")
                        .with(csrf())
                        .param("roles", "ADMIN", "USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("message", "Roles updated: bob"));

        verify(appUserRepository).save(argThat(u ->
                u.getRoles().size() == 2 && hasRole(u, "ADMIN") && hasRole(u, "USER")
        ));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles rejects empty role set")
    void updateRoles_empty_rejects() throws Exception {
        AppUser bob = AppUser.of("bob", "hash");
        when(appUserRepository.findById(21L)).thenReturn(Optional.of(bob));
        when(appRoleRepository.findByRoleNameIn(List.of())).thenReturn(List.of());

        mockMvc.perform(post("/admin/users/21/roles")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "At least one role is required."));

        verify(appUserRepository, never()).save(any());
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles rejects self-admin removal")
    void updateRoles_selfAdminRemoval_rejects() throws Exception {
        AppRole userRole = role("USER");

        AppUser admin = AppUser.of("admin", "hash");
        admin.replaceRoles(Set.of(role("ADMIN")));

        when(appUserRepository.findById(22L)).thenReturn(Optional.of(admin));
        when(appRoleRepository.findByRoleNameIn(List.of("USER")))
                .thenReturn(List.of(userRole));

        mockMvc.perform(post("/admin/users/22/roles")
                        .with(csrf())
                        .param("roles", "USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/users"))
                .andExpect(flash().attribute("error", "You cannot remove ADMIN from your own account."));

        verify(appUserRepository, never()).save(any());
    }

    @Test
    @DisplayName("POST endpoints require csrf")
    void post_requiresCsrf() throws Exception {
        mockMvc.perform(post("/admin/users")
                        .param("username", "alice")
                        .param("password", "secret123")
                        .param("roles", "USER"))
                .andExpect(status().isForbidden());
    }

    private static AppRole role(String roleName) {
        return new AppRole(roleName);
    }

    private static boolean hasRole(AppUser user, String roleName) {
        return user.getRoles().stream().anyMatch(r -> roleName.equals(r.getRoleName()));
    }
}