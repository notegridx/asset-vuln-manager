package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.AppUserDetailsService;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final AppUserDetailsService appUserDetailsService;

    @Value("${spring.h2.console.enabled:false}")
    private boolean h2ConsoleEnabled;

    @Value("${app.security.max-failed-logins:5}")
    private int maxFailedLogins;

    public SecurityConfig(AppUserDetailsService appUserDetailsService) {
        this.appUserDetailsService = appUserDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ObjectProvider<AppUserRepository> appUserRepositoryProvider,
            SecurityAuditService securityAuditService
    ) throws Exception {
        http.authenticationProvider(authenticationProvider())
                .addFilterAfter(forcePasswordChangeFilter(appUserRepositoryProvider), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(
                            "/login",
                            "/error",
                            "/styles.css",
                            "/css/**",
                            "/js/**",
                            "/images/**"
                    ).permitAll();

                    if (h2ConsoleEnabled) {
                        auth.requestMatchers("/h2-console/**").permitAll();
                    }

                    auth.requestMatchers("/account/change-password").authenticated();

                    auth.requestMatchers(
                            "/admin/users/**",
                            "/admin/settings/**"
                    ).hasRole("ADMIN");

                    auth.requestMatchers(
                            "/admin/import/**",
                            "/admin/import-runs/**",
                            "/admin/cpe/**",
                            "/admin/cve/**",
                            "/admin/kev/**",
                            "/admin/sync/**",
                            "/admin/alerts/**",
                            "/admin/canonical/**",
                            "/admin/unresolved/**",
                            "/admin/synonyms/**",
                            "/admin/aliases/**",
                            "/admin/runs/**"
                    ).hasAnyRole("ADMIN", "OPERATOR");

                    auth.requestMatchers(HttpMethod.GET,
                            "/assets/new",
                            "/assets/*/edit",
                            "/assets/*/software/new",
                            "/software/*/edit"
                    ).hasAnyRole("ADMIN", "OPERATOR");

                    auth.requestMatchers(HttpMethod.POST,
                            "/assets",
                            "/assets/*/edit",
                            "/assets/*/delete",
                            "/assets/*/software",
                            "/software/*/edit",
                            "/software/*/delete"
                    ).hasAnyRole("ADMIN", "OPERATOR");

                    auth.requestMatchers(HttpMethod.GET,
                            "/",
                            "/dashboard",
                            "/assets",
                            "/assets/*",
                            "/software",
                            "/software/*",
                            "/vulnerabilities/**",
                            "/alerts/**"
                    ).hasAnyRole("ADMIN", "OPERATOR", "VIEWER");

                    auth.anyRequest().authenticated();
                });

        if (h2ConsoleEnabled) {
            http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                    .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
        }

        http.formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(authenticationSuccessHandler(appUserRepositoryProvider, securityAuditService))
                        .failureHandler(authenticationFailureHandler(appUserRepositoryProvider, securityAuditService))
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .rememberMe(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(
            ObjectProvider<AppUserRepository> appUserRepositoryProvider,
            SecurityAuditService securityAuditService
    ) {
        return (request, response, authentication) -> {
            String target = "/dashboard";

            AppUserRepository appUserRepository = appUserRepositoryProvider.getIfAvailable();
            if (appUserRepository != null && authentication != null) {
                AppUser user = appUserRepository.findByUsername(authentication.getName()).orElse(null);
                if (user != null) {
                    user.clearLoginFailures();
                    appUserRepository.save(user);

                    securityAuditService.log(
                            "LOGIN_SUCCESS",
                            user.getUsername(),
                            user.getUsername(),
                            "SUCCESS",
                            clientIp(request),
                            "Login succeeded."
                    );

                    if (user.isPasswordChangeRequired()) {
                        target = "/account/change-password";
                    }
                }
            }

            response.sendRedirect(request.getContextPath() + target);
        };
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler(
            ObjectProvider<AppUserRepository> appUserRepositoryProvider,
            SecurityAuditService securityAuditService
    ) {
        return (request, response, exception) -> {
            String username = safe(request.getParameter("username"));
            String ip = clientIp(request);

            AppUserRepository appUserRepository = appUserRepositoryProvider.getIfAvailable();
            if (appUserRepository != null && username != null) {
                AppUser user = appUserRepository.findByUsername(username).orElse(null);
                if (user != null) {
                    int count = user.incrementFailedLoginCount();
                    boolean locked = false;

                    if (user.isAccountNonLocked() && count >= Math.max(1, maxFailedLogins)) {
                        user.lockNow();
                        locked = true;
                    }

                    appUserRepository.save(user);

                    securityAuditService.log(
                            "LOGIN_FAILURE",
                            username,
                            username,
                            "FAILURE",
                            ip,
                            "Login failed. failedLoginCount=" + user.getFailedLoginCount()
                    );

                    if (locked) {
                        securityAuditService.log(
                                "ACCOUNT_LOCKED",
                                "system",
                                username,
                                "SUCCESS",
                                ip,
                                "Account locked after too many failed login attempts."
                        );
                    }
                } else {
                    securityAuditService.log(
                            "LOGIN_FAILURE",
                            username,
                            username,
                            "FAILURE",
                            ip,
                            exception instanceof UsernameNotFoundException
                                    ? "Login failed for unknown user."
                                    : "Login failed."
                    );
                }
            } else {
                securityAuditService.log(
                        "LOGIN_FAILURE",
                        null,
                        username,
                        "FAILURE",
                        ip,
                        "Login failed."
                );
            }

            response.sendRedirect(request.getContextPath() + "/login?error");
        };
    }

    @Bean
    public OncePerRequestFilter forcePasswordChangeFilter(
            ObjectProvider<AppUserRepository> appUserRepositoryProvider
    ) {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(
                    HttpServletRequest request,
                    HttpServletResponse response,
                    FilterChain filterChain
            ) throws ServletException, IOException {
                String uri = request.getRequestURI();
                String contextPath = request.getContextPath();
                String path = (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath))
                        ? uri.substring(contextPath.length())
                        : uri;

                if (isAllowedWithoutPasswordChange(path)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                if (authentication == null
                        || !authentication.isAuthenticated()
                        || authentication instanceof AnonymousAuthenticationToken) {
                    filterChain.doFilter(request, response);
                    return;
                }

                AppUserRepository appUserRepository = appUserRepositoryProvider.getIfAvailable();
                if (appUserRepository == null) {
                    filterChain.doFilter(request, response);
                    return;
                }

                AppUser user = appUserRepository.findByUsername(authentication.getName()).orElse(null);
                if (user != null && user.isPasswordChangeRequired()) {
                    response.sendRedirect(request.getContextPath() + "/account/change-password");
                    return;
                }

                filterChain.doFilter(request, response);
            }

            private boolean isAllowedWithoutPasswordChange(String path) {
                if (path.equals("/login")
                        || path.equals("/logout")
                        || path.equals("/error")
                        || path.equals("/account/change-password")
                        || path.startsWith("/styles.css")
                        || path.startsWith("/css/")
                        || path.startsWith("/js/")
                        || path.startsWith("/images/")) {
                    return true;
                }

                return h2ConsoleEnabled && path.startsWith("/h2-console");
            }
        };
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(appUserDetailsService);
        p.setPasswordEncoder(passwordEncoder());
        return p;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return comma >= 0 ? forwarded.substring(0, comma).trim() : forwarded.trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private static String safe(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        return v.isEmpty() ? null : v;
    }
}