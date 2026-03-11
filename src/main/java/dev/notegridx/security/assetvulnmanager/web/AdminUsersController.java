package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppRole;
import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppRoleRepository;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

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

    public AdminUsersController(
            AppUserRepository appUserRepository,
            AppRoleRepository appRoleRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
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
            @RequestParam(name = "enabled", defaultValue = "false") boolean enabled
    ) {
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

        return ok(
                "message", "User created: " + u,
                "id", user.getId(),
                "username", user.getUsername(),
                "enabled", user.isEnabled(),
                "roles", user.getRoles().stream().map(AppRole::getRoleName).sorted().toList()
        );
    }

    @PostMapping("/{id}/enable")
    @ResponseBody
    @Transactional
    public Map<String, Object> enable(@PathVariable("id") Long id) {
        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found. id=" + id);
        }

        user.setEnabled(true);
        appUserRepository.save(user);

        return ok(
                "message", "User enabled: " + user.getUsername(),
                "id", user.getId(),
                "username", user.getUsername(),
                "enabled", true,
                "roles", user.getRoles().stream().map(AppRole::getRoleName).sorted().toList()
        );
    }

    @PostMapping("/{id}/disable")
    @ResponseBody
    @Transactional
    public Map<String, Object> disable(
            @PathVariable("id") Long id,
            Principal principal
    ) {
        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found. id=" + id);
        }

        if (principal != null && user.getUsername().equalsIgnoreCase(principal.getName())) {
            return error("You cannot disable your own account.");
        }

        user.setEnabled(false);
        appUserRepository.save(user);

        return ok(
                "message", "User disabled: " + user.getUsername(),
                "id", user.getId(),
                "username", user.getUsername(),
                "enabled", false,
                "roles", user.getRoles().stream().map(AppRole::getRoleName).sorted().toList()
        );
    }

    @PostMapping("/{id}/roles")
    @ResponseBody
    @Transactional
    public Map<String, Object> updateRoles(
            @PathVariable("id") Long id,
            @RequestParam(name = "roles", required = false) List<String> roleNames,
            Principal principal
    ) {
        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            return error("User not found. id=" + id);
        }

        Set<AppRole> roles = resolveRoles(roleNames);
        if (roles.isEmpty()) {
            return error("At least one role is required.");
        }

        boolean editingSelf = principal != null && user.getUsername().equalsIgnoreCase(principal.getName());
        boolean selfWouldLoseAdmin = editingSelf
                && roles.stream().noneMatch(r -> "ADMIN".equalsIgnoreCase(r.getRoleName()));

        if (selfWouldLoseAdmin) {
            return error("You cannot remove ADMIN from your own account.");
        }

        user.replaceRoles(roles);
        appUserRepository.save(user);

        return ok(
                "message", "Roles updated: " + user.getUsername(),
                "id", user.getId(),
                "username", user.getUsername(),
                "roles", user.getRoles().stream().map(AppRole::getRoleName).sorted().toList()
        );
    }

    private Set<AppRole> resolveRoles(List<String> roleNames) {
        List<String> normalized = (roleNames == null ? List.<String>of() : roleNames.stream()
                .map(AdminUsersController::safe)
                .filter(s -> s != null)
                .map(s -> s.startsWith("ROLE_") ? s.substring("ROLE_".length()) : s)
                .distinct()
                .toList());

        List<AppRole> found = appRoleRepository.findByRoleNameIn(normalized);
        return new LinkedHashSet<>(found);
    }

    private static String safe(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private Map<String, Object> error(String message) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("ok", false);
        res.put("error", message);
        return res;
    }

    private Map<String, Object> ok(Object... kv) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("ok", true);
        for (int i = 0; i + 1 < kv.length; i += 2) {
            res.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return res;
    }
}