package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AppUser;
import dev.notegridx.security.assetvulnmanager.repository.AppUserRepository;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.PasswordPolicyService;
import dev.notegridx.security.assetvulnmanager.service.SecurityAuditService;
import jakarta.servlet.http.HttpServletRequest;
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

import java.util.List;

@Controller
@RequestMapping("/account/change-password")
public class ChangePasswordController {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyService passwordPolicyService;
    private final SecurityAuditService securityAuditService;
    private final DemoModeService demoModeService;

    public ChangePasswordController(
            AppUserRepository appUserRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicyService passwordPolicyService,
            SecurityAuditService securityAuditService,
            DemoModeService demoModeService
    ) {
        this.appUserRepository = appUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicyService = passwordPolicyService;
        this.securityAuditService = securityAuditService;
        this.demoModeService = demoModeService;
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
        model.addAttribute("passwordPolicy", passwordPolicyService.loadPolicy());
        model.addAttribute("demoMode", demoModeService.isReadOnly());
        return "account/change_password";
    }

    @PostMapping
    @Transactional
    public String change(
            Authentication authentication,
            @RequestParam("currentPassword") String currentPassword,
            @RequestParam("newPassword") String newPassword,
            @RequestParam("confirmPassword") String confirmPassword,
            RedirectAttributes ra,
            HttpServletRequest request
    ) {
        demoModeService.assertWritable();

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

        if (!next.equals(confirm)) {
            ra.addFlashAttribute("error", "New password and confirmation do not match.");
            return "redirect:/account/change-password";
        }

        if (passwordEncoder.matches(next, user.getPasswordHash())) {
            ra.addFlashAttribute("error", "New password must be different from the current password.");
            return "redirect:/account/change-password";
        }

        List<String> policyErrors = passwordPolicyService.validate(next);
        if (!policyErrors.isEmpty()) {
            ra.addFlashAttribute("error", policyErrors.get(0));
            return "redirect:/account/change-password";
        }

        user.changePasswordHash(passwordEncoder.encode(next));
        user.setPasswordChangeRequired(false);
        user.clearLoginFailures();
        appUserRepository.save(user);

        securityAuditService.log(
                "PASSWORD_CHANGED",
                user.getUsername(),
                user.getUsername(),
                "SUCCESS",
                clientIp(request),
                "Password changed by authenticated user."
        );

        ra.addFlashAttribute("message", "Password updated.");
        return "redirect:/dashboard";
    }

    private static String safe(String s) {
        if (s == null) {
            return null;
        }
        String v = s.trim();
        return v.isEmpty() ? null : v;
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