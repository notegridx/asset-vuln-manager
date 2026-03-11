package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.AppUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final AppUserDetailsService appUserDetailsService;

    public SecurityConfig(AppUserDetailsService appUserDetailsService) {
        this.appUserDetailsService = appUserDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ObjectProvider<AppUserRepository> appUserRepositoryProvider
    ) throws Exception {
        http
                .authenticationProvider(authenticationProvider())
                .addFilterAfter(forcePasswordChangeFilter(appUserRepositoryProvider), UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // public
                        .requestMatchers(
                                "/login",
                                "/error",
                                "/styles.css",
                                "/css/**",
                                "/js/**",
                                "/images/**",
                                "/h2-console/**"
                        ).permitAll()

                        // any authenticated user may change their own password
                        .requestMatchers("/account/change-password").authenticated()

                        // admin only: user management
                        .requestMatchers("/admin/users/**").hasRole("ADMIN")

                        // operator + admin: operational actions
                        .requestMatchers(
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
                        ).hasAnyRole("ADMIN", "OPERATOR")

                        // read-only application screens
                        .requestMatchers(
                                "/",
                                "/dashboard",
                                "/assets/**",
                                "/software/**",
                                "/vulnerabilities/**",
                                "/alerts/**"
                        ).hasAnyRole("ADMIN", "OPERATOR", "VIEWER")

                        // fallback
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(authenticationSuccessHandler(appUserRepositoryProvider))
                        .failureUrl("/login?error")
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
            ObjectProvider<AppUserRepository> appUserRepositoryProvider
    ) {
        return (request, response, authentication) -> {
            String target = "/dashboard";

            AppUserRepository appUserRepository = appUserRepositoryProvider.getIfAvailable();
            if (appUserRepository != null && authentication != null) {
                AppUser user = appUserRepository.findByUsername(authentication.getName()).orElse(null);
                if (user != null && user.isPasswordChangeRequired()) {
                    target = "/account/change-password";
                }
            }

            response.sendRedirect(request.getContextPath() + target);
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

                Authentication authentication = org.springframework.security.core.context.SecurityContextHolder
                        .getContext()
                        .getAuthentication();

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
                return path.equals("/login")
                        || path.equals("/logout")
                        || path.equals("/error")
                        || path.equals("/account/change-password")
                        || path.startsWith("/styles.css")
                        || path.startsWith("/css/")
                        || path.startsWith("/js/")
                        || path.startsWith("/images/")
                        || path.startsWith("/h2-console");
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
}