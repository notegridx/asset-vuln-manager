package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.PasswordPolicyService;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Controller
@RequestMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUsersController {

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final SecurityAuditService securityAuditService;
    private final DemoModeService demoModeService;

    public AdminUsersController(
            AppUserRepository appUserRepository,
            AppRoleRepository appRoleRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicyService,
            SecurityAuditService securityAuditService,
            DemoModeService demoModeService
    ) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.securityAuditService = securityAuditService;
        this.demoModeService = demoModeService;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("users", appUserRepository.findAll());
        model.addAttribute("roles", appRoleRepository.findAllByOrderByRoleNameAsc());
        return "admin/users";
    }

    @PostMapping
    @ResponseBody
    @Transactional
    public Map<String, Object> create(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam(name = "roles", required = false) List<String> roleNames,
            @RequestParam(name = "enabled", defaultValue = "false") boolean enabled,
            Principal principal,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

        String u = safe(username);
        String p = safe(password);

        if (u == null) {
            return error("Username is required.");
        }
        if (p == null) {
            return error("Password is required.");
        }
        if (appUserRepository.existsByUsername(u)) {
            return error("Username already exists: " + u);
        }

        Set<AppRole> roles = resolveRoles(roleNames);
        if (roles.isEmpty()) {
            return error("At least one role is required.");
        }

        AppUser user = AppUser.of(u, passwordEncoder.encode(p));
        user.setEnabled(enabled);
        user.setAccountNonLocked(true);
        user.replaceRoles(roles);

        appUserRepository.save(user);

        securityAuditService.log(
                "USER_CREATED",
                actor(principal),
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "User created."
        );

        return okUser("User created.", user);
    }

    @PostMapping("/{id}/enable")
    @ResponseBody
    @Transactional
    public Map<String, Object> enable(
            @PathVariable("id") Long id,
            Principal principal,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found.");
        }

        user.setEnabled(true);
        appUserRepository.save(user);

        securityAuditService.log(
                "USER_ENABLED",
                actor(principal),
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "User enabled."
        );

        return okUser("User enabled.", user);
    }

    @PostMapping("/{id}/disable")
    @ResponseBody
    @Transactional
    public Map<String, Object> disable(
            @PathVariable("id") Long id,
            Principal principal,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found.");
        }

        String actor = actor(principal);
        if (actor != null && actor.equalsIgnoreCase(user.getUsername())) {
            return error("You cannot disable your own account.");
        }

        user.setEnabled(false);
        appUserRepository.save(user);

        securityAuditService.log(
                "USER_DISABLED",
                actor,
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "User disabled."
        );

        return okUser("User disabled.", user);
    }

    @PostMapping("/{id}/unlock")
    @ResponseBody
    @Transactional
    public Map<String, Object> unlock(
            @PathVariable("id") Long id,
            Principal principal,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found.");
        }

        user.unlock();
        appUserRepository.save(user);

        securityAuditService.log(
                "USER_UNLOCKED",
                actor(principal),
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "User unlocked and failed login counter reset."
        );

        return okUser("User unlocked.", user);
    }

    @PostMapping("/{id}/reset-password")
    @ResponseBody
    @Transactional
    public Map<String, Object> resetPassword(
            @PathVariable("id") Long id,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            Principal principal,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found.");
        }

        String next = safe(newPassword);
        String confirm = safe(confirmPassword);

        if (next == null) {
            return error("Temporary password is required.");
        }
        if (confirm == null) {
            return error("Password confirmation is required.");
        }
        if (!next.equals(confirm)) {
            return error("Temporary password and confirmation do not match.");
        }

        List<String> passwordErrors = passwordPolicyService.validate(next);
        if (!passwordErrors.isEmpty()) {
            return error(String.join(" ", passwordErrors));
        }

        user.changePasswordHash(passwordEncoder.encode(next));
        user.setPasswordChangeRequired(true);
        user.unlock();

        appUserRepository.save(user);

        securityAuditService.log(
                "PASSWORD_RESET_BY_ADMIN",
                actor(principal),
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "Password reset by administrator. passwordChangeRequired=true"
        );

        return okUser("Temporary password updated.", user);
    }

    @PostMapping("/{id}/roles")
    @ResponseBody
    @Transactional
    public Map<String, Object> updateRoles(
            @PathVariable("id") Long id,
            @RequestParam(name = "roles", required = false) List<String> roleNames,
            Principal principal,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found.");
        }

        Set<AppRole> roles = resolveRoles(roleNames);
        if (roles.isEmpty()) {
            return error("At least one role is required.");
        }

        String actor = actor(principal);
        if (actor != null && actor.equalsIgnoreCase(user.getUsername())) {
            boolean keepsAdmin = roles.stream().anyMatch(r -> "ADMIN".equalsIgnoreCase(r.getRoleName()));
            if (!keepsAdmin) {
                return error("You cannot remove ADMIN from your own account.");
            }
        }

        user.replaceRoles(roles);
        appUserRepository.save(user);

        securityAuditService.log(
                "USER_ROLES_UPDATED",
                actor,
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "Roles updated to: " + roles.stream().map(AppRole::getRoleName).sorted().toList()
        );

        return okUser("Roles updated.", user);
    }

    private Set<AppRole> resolveRoles(List<String> roleNames) {
        Set<String> names = new LinkedHashSet<>();
        if (roleNames != null) {
            for (String roleName : roleNames) {
                String v = safe(roleName);
                if (v != null) {
                    names.add(v.toUpperCase());
                }
            }
        }
        if (names.isEmpty()) {
            return Set.of();
        }
        return new LinkedHashSet<>(appRoleRepository.findByRoleNameIn(names.stream().toList()));
    }

    private static Map<String, Object> ok(String message, String username) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("message", message);
        m.put("username", username);
        return m;
    }

    private static Map<String, Object> okUser(String message, AppUser user) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("message", message);

        if (user != null) {
            m.put("id", user.getId());
            m.put("username", user.getUsername());
            m.put("enabled", user.isEnabled());
            m.put("accountNonLocked", user.isAccountNonLocked());
            m.put("passwordChangeRequired", user.isPasswordChangeRequired());
            m.put("failedLoginCount", user.getFailedLoginCount());
            m.put("roles", user.getRoles().stream()
                    .map(AppRole::getRoleName)
                    .sorted()
                    .toList());
        }

        return m;
    }

    private static Map<String, Object> error(String message) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("message", message);
        return m;
    }

    private static String safe(String s) {
        if (s == null) {
            return null;
        }
        String v = s.trim();
        return v.isEmpty() ? null : v;
    }

    private static String actor(Principal principal) {
        return principal == null ? null : principal.getName();
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
}