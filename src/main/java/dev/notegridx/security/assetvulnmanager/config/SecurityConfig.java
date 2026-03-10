package dev.notegridx.security.assetvulnmanager.config;

import dev.notegridx.security.assetvulnmanager.service.AppUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private final AppUserDetailsService appUserDetailsService;

    public SecurityConfig(AppUserDetailsService appUserDetailsService) {
        this.appUserDetailsService = appUserDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authenticationProvider(authenticationProvider())
                .authorizeHttpRequests(auth -> auth
                        // public
                        .requestMatchers(
                                "/login",
                                "/error",
                                "/styles.css",
                                "/css/**",
                                "/js/**",
                                "/images/**"
                        ).permitAll()

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
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
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