package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.PasswordPolicyService;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
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

@WebMvcTest(controllers = ChangePasswordController.class)
@ActiveProfiles("mysqltest")
@Import(TestSecurityConfig.class)
class ChangePasswordControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AppUserRepository appUserRepository;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private PasswordPolicyService passwordPolicyService;

    @MockitoBean
    private SecurityAuditService securityAuditService;

    @Test
    @DisplayName("GET /account/change-password redirects to login when unauthenticated")
    void form_redirectsToLogin_whenUnauthenticated() throws Exception {
        mockMvc.perform(get("/account/change-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("GET /account/change-password renders form for authenticated user")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void form_rendersForAuthenticatedUser() throws Exception {
        AppUser user = AppUser.of("alice", "hash");
        user.setPasswordChangeRequired(true);
        user.setBootstrapAdmin(true);

        PasswordPolicyService.PasswordPolicy policy =
                new PasswordPolicyService.PasswordPolicy(12, true, true, true, true);

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordPolicyService.loadPolicy()).thenReturn(policy);

        mockMvc.perform(get("/account/change-password"))
                .andExpect(status().isOk())
                .andExpect(view().name("account/change_password"))
                .andExpect(model().attribute("username", "alice"))
                .andExpect(model().attribute("passwordChangeRequired", true))
                .andExpect(model().attribute("bootstrapAdmin", true))
                .andExpect(model().attribute("passwordPolicy", policy));
    }

    @Test
    @DisplayName("GET /account/change-password redirects to login when user is not found")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void form_redirectsToLogin_whenUserNotFound() throws Exception {
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.empty());

        mockMvc.perform(get("/account/change-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));
    }

    @Test
    @DisplayName("POST /account/change-password updates password and clears passwordChangeRequired")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_updatesPassword() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        user.setPasswordChangeRequired(true);
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "OLD_HASH")).thenReturn(true);
        when(passwordEncoder.matches("new-secret1", "OLD_HASH")).thenReturn(false);
        when(passwordPolicyService.validate("new-secret1")).thenReturn(List.of());
        when(passwordEncoder.encode("new-secret1")).thenReturn("NEW_HASH");
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "new-secret1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"))
                .andExpect(flash().attribute("message", "Password updated."));

        verify(passwordEncoder).matches("current-pass", "OLD_HASH");
        verify(passwordEncoder).matches("new-secret1", "OLD_HASH");
        verify(passwordPolicyService).validate("new-secret1");
        verify(passwordEncoder).encode("new-secret1");

        verify(appUserRepository).save(argThat(saved ->
                "alice".equals(saved.getUsername())
                        && !saved.isPasswordChangeRequired()
                        && saved.getFailedLoginCount() == 0
                        && saved.getLastFailedLoginAt() == null
        ));

        verify(securityAuditService).log(
                eq("PASSWORD_CHANGED"),
                eq("alice"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("Password changed by authenticated user.")
        );
    }

    @Test
    @DisplayName("POST /account/change-password redirects to login when unauthenticated")
    void change_redirectsToLogin_whenUnauthenticated() throws Exception {
        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "new-secret1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password redirects to login when user is not found")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_redirectsToLogin_whenUserNotFound() throws Exception {
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.empty());

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "new-secret1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login"));

        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects blank current password")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsBlankCurrentPassword() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "   ")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "new-secret1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "Current password is required."));

        verify(passwordEncoder, never()).matches(any(), any());
        verify(passwordPolicyService, never()).validate(any());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects blank new password")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsBlankNewPassword() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "   ")
                        .param("confirmPassword", "new-secret1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "New password is required."));

        verify(passwordEncoder, never()).matches(any(), any());
        verify(passwordPolicyService, never()).validate(any());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects blank confirmation")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsBlankConfirmation() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "   "))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "Password confirmation is required."));

        verify(passwordEncoder, never()).matches(any(), any());
        verify(passwordPolicyService, never()).validate(any());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects incorrect current password")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsIncorrectCurrentPassword() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-pass", "OLD_HASH")).thenReturn(false);

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "wrong-pass")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "new-secret1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "Current password is incorrect."));

        verify(passwordEncoder).matches("wrong-pass", "OLD_HASH");
        verify(passwordPolicyService, never()).validate(any());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects password that violates policy")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsPolicyViolation() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "OLD_HASH")).thenReturn(true);
        when(passwordEncoder.matches("short", "OLD_HASH")).thenReturn(false);
        when(passwordPolicyService.validate("short"))
                .thenReturn(List.of("New password must be at least 12 characters."));

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "short")
                        .param("confirmPassword", "short"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "New password must be at least 12 characters."));

        verify(passwordEncoder).matches("current-pass", "OLD_HASH");
        verify(passwordEncoder).matches("short", "OLD_HASH");
        verify(passwordPolicyService).validate("short");
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects confirmation mismatch")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsConfirmationMismatch() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "OLD_HASH")).thenReturn(true);

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "new-secret1")
                        .param("confirmPassword", "new-secret2"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "New password and confirmation do not match."));

        verify(passwordEncoder).matches("current-pass", "OLD_HASH");
        verify(passwordPolicyService, never()).validate(any());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("POST /account/change-password rejects reusing current password")
    @WithMockUser(username = "alice", roles = "ADMIN")
    void change_rejectsReusingCurrentPassword() throws Exception {
        AppUser user = AppUser.of("alice", "OLD_HASH");
        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-pass", "OLD_HASH")).thenReturn(true);
        when(passwordEncoder.matches("same-password", "OLD_HASH")).thenReturn(true);

        mockMvc.perform(post("/account/change-password")
                        .with(csrf())
                        .param("currentPassword", "current-pass")
                        .param("newPassword", "same-password")
                        .param("confirmPassword", "same-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/account/change-password"))
                .andExpect(flash().attribute("error", "New password must be different from the current password."));

        verify(passwordEncoder).matches("current-pass", "OLD_HASH");
        verify(passwordEncoder).matches("same-password", "OLD_HASH");
        verify(passwordPolicyService, never()).validate(any());
        verify(passwordEncoder, never()).encode(any());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService, never()).log(any(), any(), any(), any(), any(), any());
    }
}