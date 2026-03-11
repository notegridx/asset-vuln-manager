package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/account/change-password")
public class ChangePasswordController {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    public ChangePasswordController(
            AppUserRepository appUserRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public String form(Authentication authentication, Model model) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        AppUser user = appUserRepository.findByUsername(authentication.getName()).orElse(null);
        if (user == null) {
            return "redirect:/login";
        }

        model.addAttribute("username", user.getUsername());
        model.addAttribute("passwordChangeRequired", user.isPasswordChangeRequired());
        model.addAttribute("bootstrapAdmin", user.isBootstrapAdmin());
        return "account/change_password";
    }

    @PostMapping
    @Transactional
    public String change(
            Authentication authentication,
            @RequestParam("currentPassword") String currentPassword,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            RedirectAttributes ra
    ) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return "redirect:/login";
        }

        AppUser user = appUserRepository.findByUsername(authentication.getName()).orElse(null);
        if (user == null) {
            return "redirect:/login";
        }

        String current = safe(currentPassword);
        String next = safe(newPassword);
        String confirm = safe(confirmPassword);

        if (current == null) {
            ra.addFlashAttribute("error", "Current password is required.");
            return "redirect:/account/change-password";
        }

        if (next == null) {
            ra.addFlashAttribute("error", "New password is required.");
            return "redirect:/account/change-password";
        }

        if (confirm == null) {
            ra.addFlashAttribute("error", "Password confirmation is required.");
            return "redirect:/account/change-password";
        }

        if (!passwordEncoder.matches(current, user.getPasswordHash())) {
            ra.addFlashAttribute("error", "Current password is incorrect.");
            return "redirect:/account/change-password";
        }

        if (next.length() < 8) {
            ra.addFlashAttribute("error", "New password must be at least 8 characters.");
            return "redirect:/account/change-password";
        }

        if (!next.equals(confirm)) {
            ra.addFlashAttribute("error", "New password and confirmation do not match.");
            return "redirect:/account/change-password";
        }

        if (passwordEncoder.matches(next, user.getPasswordHash())) {
            ra.addFlashAttribute("error", "New password must be different from the current password.");
            return "redirect:/account/change-password";
        }

        user.changePasswordHash(passwordEncoder.encode(next));
        user.setPasswordChangeRequired(false);
        appUserRepository.save(user);

        ra.addFlashAttribute("message", "Password updated.");
        return "redirect:/dashboard";
    }

    private String safe(String s) {
        if (s == null) return null;
        String v = s.trim();
        return v.isEmpty() ? null : v;
    }
}