package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.SystemSetting;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
public class PasswordPolicyService {

    public static final String KEY_AUTH_PASSWORD_MIN_LENGTH = "auth.password.min-length";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_UPPER = "auth.password.require-upper";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_LOWER = "auth.password.require-lower";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_DIGIT = "auth.password.require-digit";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_SYMBOL = "auth.password.require-symbol";

    private final SystemSettingRepository systemSettingRepository;

    public PasswordPolicyService(SystemSettingRepository systemSettingRepository) {
        this.systemSettingRepository = systemSettingRepository;
    }

    @Transactional(readOnly = true)
    public PasswordPolicy loadPolicy() {
        return new PasswordPolicy(
                getInt(KEY_AUTH_PASSWORD_MIN_LENGTH, 8),
                getBool(KEY_AUTH_PASSWORD_REQUIRE_UPPER, false),
                getBool(KEY_AUTH_PASSWORD_REQUIRE_LOWER, false),
                getBool(KEY_AUTH_PASSWORD_REQUIRE_DIGIT, false),
                getBool(KEY_AUTH_PASSWORD_REQUIRE_SYMBOL, false)
        );
    }

    @Transactional(readOnly = true)
    public List<String> validate(String rawPassword) {
        PasswordPolicy policy = loadPolicy();
        List<String> errors = new ArrayList<>();

        if (rawPassword == null || rawPassword.isBlank()) {
            errors.add("New password is required.");
            return errors;
        }

        if (rawPassword.length() < policy.minLength()) {
            errors.add("New password must be at least " + policy.minLength() + " characters.");
        }

        if (policy.requireUpper() && !containsUpper(rawPassword)) {
            errors.add("New password must include at least one uppercase letter.");
        }

        if (policy.requireLower() && !containsLower(rawPassword)) {
            errors.add("New password must include at least one lowercase letter.");
        }

        if (policy.requireDigit() && !containsDigit(rawPassword)) {
            errors.add("New password must include at least one digit.");
        }

        if (policy.requireSymbol() && !containsSymbol(rawPassword)) {
            errors.add("New password must include at least one symbol.");
        }

        return errors;
    }

    private int getInt(String key, int defaultValue) {
        String raw = get(key, String.valueOf(defaultValue));
        try {
            return Integer.parseInt(raw);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private boolean getBool(String key, boolean defaultValue) {
        String raw = get(key, String.valueOf(defaultValue));
        return "true".equalsIgnoreCase(raw);
    }

    private String get(String key, String defaultValue) {
        return systemSettingRepository.findById(key)
                .map(SystemSetting::getSettingValue)
                .orElse(defaultValue);
    }

    private boolean containsUpper(String s) {
        return s.chars().anyMatch(Character::isUpperCase);
    }

    private boolean containsLower(String s) {
        return s.chars().anyMatch(Character::isLowerCase);
    }

    private boolean containsDigit(String s) {
        return s.chars().anyMatch(Character::isDigit);
    }

    private boolean containsSymbol(String s) {
        return s.chars().anyMatch(ch -> !Character.isLetterOrDigit(ch) && !Character.isWhitespace(ch));
    }

    public record PasswordPolicy(
            int minLength,
            boolean requireUpper,
            boolean requireLower,
            boolean requireDigit,
            boolean requireSymbol
    ) {
    }
}