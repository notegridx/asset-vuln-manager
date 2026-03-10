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
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;
import java.util.LinkedHashSet;
import java.util.List;
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
    @Transactional
    public String create(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam(name = "roles", required = false) List<String> roleNames,
            @RequestParam(name = "enabled", defaultValue = "false") boolean enabled,
            RedirectAttributes ra
    ) {
        String u = safe(username);
        String p = safe(password);

        if (u == null) {
            ra.addFlashAttribute("error", "Username is required.");
            return "redirect:/admin/users";
        }
        if (p == null) {
            ra.addFlashAttribute("error", "Password is required.");
            return "redirect:/admin/users";
        }
        if (appUserRepository.existsByUsername(u)) {
            ra.addFlashAttribute("error", "Username already exists: " + u);
            return "redirect:/admin/users";
        }

        Set<AppRole> roles = resolveRoles(roleNames);
        if (roles.isEmpty()) {
            ra.addFlashAttribute("error", "At least one role is required.");
            return "redirect:/admin/users";
        }

        AppUser user = AppUser.of(u, passwordEncoder.encode(p));
        user.setEnabled(enabled);
        user.setAccountNonLocked(true);
        user.replaceRoles(roles);

        appUserRepository.save(user);

        ra.addFlashAttribute("message", "User created: " + u);
        return "redirect:/admin/users";
    }

    @PostMapping("/{id}/enable")
    @Transactional
    public String enable(
            @PathVariable("id") Long id,
            RedirectAttributes ra
    ) {
        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            ra.addFlashAttribute("error", "User not found. id=" + id);
            return "redirect:/admin/users";
        }

        user.setEnabled(true);
        appUserRepository.save(user);

        ra.addFlashAttribute("message", "User enabled: " + user.getUsername());
        return "redirect:/admin/users";
    }

    @PostMapping("/{id}/disable")
    @Transactional
    public String disable(
            @PathVariable("id") Long id,
            Principal principal,
            RedirectAttributes ra
    ) {
        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            ra.addFlashAttribute("error", "User not found. id=" + id);
            return "redirect:/admin/users";
        }

        if (principal != null && user.getUsername().equalsIgnoreCase(principal.getName())) {
            ra.addFlashAttribute("error", "You cannot disable your own account.");
            return "redirect:/admin/users";
        }

        user.setEnabled(false);
        appUserRepository.save(user);

        ra.addFlashAttribute("message", "User disabled: " + user.getUsername());
        return "redirect:/admin/users";
    }

    @PostMapping("/{id}/roles")
    @Transactional
    public String updateRoles(
            @PathVariable("id") Long id,
            @RequestParam(name = "roles", required = false) List<String> roleNames,
            Principal principal,
            RedirectAttributes ra
    ) {
        AppUser user = appUserRepository.findById(id).orElse(null);
        if (user == null) {
            ra.addFlashAttribute("error", "User not found. id=" + id);
            return "redirect:/admin/users";
        }

        Set<AppRole> roles = resolveRoles(roleNames);
        if (roles.isEmpty()) {
            ra.addFlashAttribute("error", "At least one role is required.");
            return "redirect:/admin/users";
        }

        boolean editingSelf = principal != null && user.getUsername().equalsIgnoreCase(principal.getName());
        boolean selfWouldLoseAdmin = editingSelf && roles.stream().noneMatch(r -> "ADMIN".equalsIgnoreCase(r.getRoleName()));
        if (selfWouldLoseAdmin) {
            ra.addFlashAttribute("error", "You cannot remove ADMIN from your own account.");
            return "redirect:/admin/users";
        }

        user.replaceRoles(roles);
        appUserRepository.save(user);

        ra.addFlashAttribute("message", "Roles updated: " + user.getUsername());
        return "redirect:/admin/users";
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
}