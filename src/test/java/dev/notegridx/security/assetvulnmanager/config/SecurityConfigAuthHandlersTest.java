package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.domain.SystemSetting;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import dev.notegridx.security.assetvulnmanager.service.AppUserDetailsService;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class SecurityConfigAuthHandlersTest {

    private static final String KEY_AUTH_ACCOUNT_LOCK_ENABLED = "auth.account-lock.enabled";
    private static final String KEY_AUTH_MAX_FAILED_LOGINS = "auth.max-failed-logins";

    @Test
    @DisplayName("authentication failure increments failed login count")
    void failure_incrementsFailedLoginCount() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        stubAccountLockSettings(systemSettingRepository, true, 5);

        AppUser user = AppUser.of("alice", "hash");
        user.addRole(AppRole.of("ADMIN"));

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationFailureHandler handler = securityConfig.authenticationFailureHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        request.addParameter("username", "alice");
        request.setRemoteAddr("127.0.0.1");

        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        assertEquals(1, user.getFailedLoginCount());
        assertTrue(user.isAccountNonLocked());
        assertNull(user.getLockedAt());
        assertEquals("/login?error&reason=bad-credentials", response.getRedirectedUrl());

        verify(appUserRepository).save(user);
        verify(securityAuditService).log(
                eq("LOGIN_FAILURE"),
                eq("alice"),
                eq("alice"),
                eq("FAILURE"),
                eq("127.0.0.1"),
                eq("Login failed. failedLoginCount=1")
        );
        verify(securityAuditService, never()).log(
                eq("ACCOUNT_LOCKED"),
                any(),
                any(),
                any(),
                any(),
                any()
        );
    }

    @Test
    @DisplayName("authentication failure locks account at threshold")
    void failure_locksAccountAtThreshold() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        stubAccountLockSettings(systemSettingRepository, true, 3);

        AppUser user = AppUser.of("alice", "hash");
        user.addRole(AppRole.of("ADMIN"));
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationFailureHandler handler = securityConfig.authenticationFailureHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        request.addParameter("username", "alice");
        request.setRemoteAddr("10.0.0.5");

        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        assertEquals(3, user.getFailedLoginCount());
        assertFalse(user.isAccountNonLocked());
        assertTrue(user.getLockedAt() != null);
        assertEquals("/login?error&reason=locked", response.getRedirectedUrl());

        verify(appUserRepository).save(user);
        verify(securityAuditService).log(
                eq("LOGIN_FAILURE"),
                eq("alice"),
                eq("alice"),
                eq("FAILURE"),
                eq("10.0.0.5"),
                eq("Login failed. failedLoginCount=3")
        );
        verify(securityAuditService).log(
                eq("ACCOUNT_LOCKED"),
                eq("system"),
                eq("alice"),
                eq("SUCCESS"),
                eq("10.0.0.5"),
                eq("Account locked after too many failed login attempts.")
        );
    }

    @Test
    @DisplayName("authentication failure redirects disabled user with disabled reason")
    void failure_disabledUser_redirectsWithDisabledReason() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        stubAccountLockSettings(systemSettingRepository, true, 5);

        AppUser user = AppUser.of("alice", "hash");
        user.addRole(AppRole.of("ADMIN"));
        user.setEnabled(false);

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationFailureHandler handler = securityConfig.authenticationFailureHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        request.addParameter("username", "alice");
        request.setRemoteAddr("172.16.0.20");

        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        assertEquals(1, user.getFailedLoginCount());
        assertTrue(user.isAccountNonLocked());
        assertNull(user.getLockedAt());
        assertEquals("/login?error&reason=disabled", response.getRedirectedUrl());

        verify(appUserRepository).save(user);
        verify(securityAuditService).log(
                eq("LOGIN_FAILURE"),
                eq("alice"),
                eq("alice"),
                eq("FAILURE"),
                eq("172.16.0.20"),
                eq("Login failed. failedLoginCount=1")
        );
        verify(securityAuditService, never()).log(
                eq("ACCOUNT_LOCKED"),
                any(),
                any(),
                any(),
                any(),
                any()
        );
    }

    @Test
    @DisplayName("authentication success clears failure counters and redirects to dashboard")
    void success_clearsFailures_andRedirectsDashboard() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        AppUser user = AppUser.of("alice", "hash");
        user.addRole(AppRole.of("ADMIN"));
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationSuccessHandler handler = securityConfig.authenticationSuccessHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        request.setRemoteAddr("127.0.0.1");

        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authentication = new UsernamePasswordAuthenticationToken("alice", "pw");

        handler.onAuthenticationSuccess(request, response, authentication);

        assertEquals(0, user.getFailedLoginCount());
        assertNull(user.getLastFailedLoginAt());
        assertEquals("/dashboard", response.getRedirectedUrl());

        verify(appUserRepository).save(user);
        verify(securityAuditService).log(
                eq("LOGIN_SUCCESS"),
                eq("alice"),
                eq("alice"),
                eq("SUCCESS"),
                eq("127.0.0.1"),
                eq("Login succeeded.")
        );
    }

    @Test
    @DisplayName("authentication success redirects to change-password when required")
    void success_redirectsToChangePassword_whenRequired() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        AppUser user = AppUser.of("alice", "hash");
        user.setPasswordChangeRequired(true);

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationSuccessHandler handler = securityConfig.authenticationSuccessHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");

        MockHttpServletResponse response = new MockHttpServletResponse();

        Authentication authentication = new TestingAuthenticationToken("alice", "pw");

        handler.onAuthenticationSuccess(request, response, authentication);

        assertEquals("/account/change-password", response.getRedirectedUrl());
        verify(securityAuditService).log(
                eq("LOGIN_SUCCESS"),
                eq("alice"),
                eq("alice"),
                eq("SUCCESS"),
                any(),
                eq("Login succeeded.")
        );
    }

    @Test
    @DisplayName("authentication failure for unknown user only writes audit log")
    void failure_unknownUser_onlyAudits() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        stubAccountLockSettings(systemSettingRepository, true, 5);

        when(appUserRepository.findByUsername("ghost")).thenReturn(Optional.empty());

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationFailureHandler handler = securityConfig.authenticationFailureHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        request.addParameter("username", "ghost");
        request.setRemoteAddr("192.168.1.10");

        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        assertEquals("/login?error&reason=bad-credentials", response.getRedirectedUrl());
        verify(appUserRepository, never()).save(any(AppUser.class));
        verify(securityAuditService).log(
                eq("LOGIN_FAILURE"),
                eq("ghost"),
                eq("ghost"),
                eq("FAILURE"),
                eq("192.168.1.10"),
                eq("Login failed.")
        );
    }

    @Test
    @DisplayName("authentication failure does not lock account when account lock is disabled")
    void failure_doesNotLock_whenAccountLockDisabled() throws Exception {
        AppUserRepository appUserRepository = mock(AppUserRepository.class);
        AppUserDetailsService appUserDetailsService = mock(AppUserDetailsService.class);
        SecurityAuditService securityAuditService = mock(SecurityAuditService.class);
        SystemSettingRepository systemSettingRepository = mock(SystemSettingRepository.class);

        stubAccountLockSettings(systemSettingRepository, false, 3);

        AppUser user = AppUser.of("alice", "hash");
        user.addRole(AppRole.of("ADMIN"));
        user.incrementFailedLoginCount();
        user.incrementFailedLoginCount();

        when(appUserRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(appUserRepository.save(any(AppUser.class))).thenAnswer(inv -> inv.getArgument(0));

        SecurityConfig securityConfig = new SecurityConfig(appUserDetailsService, systemSettingRepository);

        AuthenticationFailureHandler handler = securityConfig.authenticationFailureHandler(
                providerOf(appUserRepository),
                securityAuditService
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("");
        request.addParameter("username", "alice");
        request.setRemoteAddr("10.0.0.5");

        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        assertEquals(3, user.getFailedLoginCount());
        assertTrue(user.isAccountNonLocked());
        assertNull(user.getLockedAt());
        assertEquals("/login?error&reason=bad-credentials", response.getRedirectedUrl());

        verify(securityAuditService, never()).log(
                eq("ACCOUNT_LOCKED"),
                any(),
                any(),
                any(),
                any(),
                any()
        );
    }

    private static void stubAccountLockSettings(
            SystemSettingRepository systemSettingRepository,
            boolean enabled,
            int maxFailedLogins
    ) {
        when(systemSettingRepository.findById(KEY_AUTH_ACCOUNT_LOCK_ENABLED))
                .thenReturn(Optional.of(SystemSetting.of(
                        KEY_AUTH_ACCOUNT_LOCK_ENABLED,
                        String.valueOf(enabled),
                        "tester"
                )));
        when(systemSettingRepository.findById(KEY_AUTH_MAX_FAILED_LOGINS))
                .thenReturn(Optional.of(SystemSetting.of(
                        KEY_AUTH_MAX_FAILED_LOGINS,
                        String.valueOf(maxFailedLogins),
                        "tester"
                )));
    }

    private static ObjectProvider<AppUserRepository> providerOf(AppUserRepository appUserRepository) {
        StaticListableBeanFactory beanFactory = new StaticListableBeanFactory();
        beanFactory.addBean("appUserRepository", appUserRepository);
        return beanFactory.getBeanProvider(AppUserRepository.class);
    }
}