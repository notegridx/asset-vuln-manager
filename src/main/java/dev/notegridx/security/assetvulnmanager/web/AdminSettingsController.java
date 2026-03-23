package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SystemSetting;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.web.form.AdminSettingsForm;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class AdminSettingsController {

    public static final String KEY_CANONICAL_NORMALIZE_VENDOR_EXTRACT_DN_ORGANIZATION =
            "canonical.normalize.vendor.extract-dn-organization";
    public static final String KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_COMMON_PHRASES =
            "canonical.normalize.vendor.remove-common-phrases";
    public static final String KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_LEGAL_SUFFIX =
            "canonical.normalize.vendor.remove-legal-suffix";
    public static final String KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_ARCH_PAREN =
            "canonical.normalize.product.remove-arch-paren";
    public static final String KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_LOCALE_TAG =
            "canonical.normalize.product.remove-locale-tag";
    public static final String KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_JAVA_UPDATE_SUFFIX =
            "canonical.normalize.product.remove-java-update-suffix";
    public static final String KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_VERSION_SUFFIX =
            "canonical.normalize.product.remove-version-suffix";

    public static final String KEY_CANONICAL_CANDIDATE_MIN_CHARS = "canonical.candidate.min-chars";
    public static final String KEY_CANONICAL_CANDIDATE_EXACT_LIMIT = "canonical.candidate.exact-limit";
    public static final String KEY_CANONICAL_CANDIDATE_OTHER_LIMIT = "canonical.candidate.other-limit";
    public static final String KEY_CANONICAL_CANDIDATE_UNRESOLVED_LIMIT = "canonical.candidate.unresolved-limit";

    public static final String KEY_CANONICAL_AUTOLINK_USE_SYNONYM = "canonical.autolink.use-synonym";
    public static final String KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK = "canonical.autolink.use-token-fallback";
    public static final String KEY_CANONICAL_AUTOLINK_CONTAINS_MATCH = "canonical.autolink.contains-match";
    public static final String KEY_CANONICAL_AUTOLINK_VENDOR_UNIQUE_REQUIRED = "canonical.autolink.vendor-unique-required";
    public static final String KEY_CANONICAL_AUTOLINK_PRODUCT_UNIQUE_REQUIRED = "canonical.autolink.product-unique-required";
    public static final String KEY_CANONICAL_AUTOLINK_MIN_SCORE = "canonical.autolink.min-score";
    public static final String KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW = "canonical.autolink.skip-disabled-row";

    public static final String KEY_CANONICAL_EXPLAIN_SHOW_REASON = "canonical.explain.show-reason";
    public static final String KEY_CANONICAL_EXPLAIN_SHOW_SCORE_BREAKDOWN = "canonical.explain.show-score-breakdown";
    public static final String KEY_CANONICAL_EXPLAIN_SHOW_SKIP_REASON = "canonical.explain.show-skip-reason";

    public static final String KEY_VULN_SUGGEST_MAX_ITEMS = "vuln.suggest.max-items";
    public static final String KEY_VULN_SUGGEST_VENDOR_EXACT_SCORE = "vuln.suggest.vendor-exact-score";
    public static final String KEY_VULN_SUGGEST_VENDOR_PARTIAL_SCORE = "vuln.suggest.vendor-partial-score";
    public static final String KEY_VULN_SUGGEST_PRODUCT_EXACT_SCORE = "vuln.suggest.product-exact-score";
    public static final String KEY_VULN_SUGGEST_TOKEN_OVERLAP_SCORE = "vuln.suggest.token-overlap-score";
    public static final String KEY_VULN_SUGGEST_PARTIAL_MATCH_SCORE = "vuln.suggest.partial-match-score";
    public static final String KEY_VULN_SUGGEST_ACTIVE_ONLY = "vuln.suggest.active-only";
    public static final String KEY_VULN_SUGGEST_SHOW_REASONS = "vuln.suggest.show-reasons";

    public static final String KEY_AUTH_PASSWORD_MIN_LENGTH = "auth.password.min-length";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_UPPER = "auth.password.require-upper";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_LOWER = "auth.password.require-lower";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_DIGIT = "auth.password.require-digit";
    public static final String KEY_AUTH_PASSWORD_REQUIRE_SYMBOL = "auth.password.require-symbol";

    private final SystemSettingRepository systemSettingRepository;
    private final DemoModeService demoModeService;

    public AdminSettingsController(
            SystemSettingRepository systemSettingRepository,
            DemoModeService demoModeService
    ) {
        this.systemSettingRepository = systemSettingRepository;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/settings")
    public String view(Model model) {
        model.addAttribute("settingsForm", loadForm());
        putMeta(model);
        return "admin/settings";
    }

    @PostMapping("/admin/settings")
    @Transactional
    public String save(
            @ModelAttribute("settingsForm") AdminSettingsForm form,
            Authentication authentication,
            RedirectAttributes ra
    ) {
        demoModeService.assertWritable();

        String username = authentication != null ? authentication.getName() : "unknown";

        putBool(
                KEY_CANONICAL_NORMALIZE_VENDOR_EXTRACT_DN_ORGANIZATION,
                form.isCanonicalNormalizeVendorExtractDnOrganization(),
                username
        );
        putBool(
                KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_COMMON_PHRASES,
                form.isCanonicalNormalizeVendorRemoveCommonPhrases(),
                username
        );
        putBool(
                KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_LEGAL_SUFFIX,
                form.isCanonicalNormalizeVendorRemoveLegalSuffix(),
                username
        );
        putBool(
                KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_ARCH_PAREN,
                form.isCanonicalNormalizeProductRemoveArchParen(),
                username
        );
        putBool(
                KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_LOCALE_TAG,
                form.isCanonicalNormalizeProductRemoveLocaleTag(),
                username
        );
        putBool(
                KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_JAVA_UPDATE_SUFFIX,
                form.isCanonicalNormalizeProductRemoveJavaUpdateSuffix(),
                username
        );
        putBool(
                KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_VERSION_SUFFIX,
                form.isCanonicalNormalizeProductRemoveVersionSuffix(),
                username
        );

        putInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, clamp(form.getCanonicalCandidateMinChars(), 1, 10, 2), username);
        putInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, clamp(form.getCanonicalCandidateExactLimit(), 1, 50, 5), username);
        putInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, clamp(form.getCanonicalCandidateOtherLimit(), 1, 100, 30), username);
        putInt(KEY_CANONICAL_CANDIDATE_UNRESOLVED_LIMIT, clamp(form.getCanonicalCandidateUnresolvedLimit(), 1, 100, 20), username);

        putBool(KEY_CANONICAL_AUTOLINK_USE_SYNONYM, form.isCanonicalAutolinkUseSynonym(), username);
        putBool(KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK, form.isCanonicalAutolinkUseTokenFallback(), username);
        putBool(KEY_CANONICAL_AUTOLINK_CONTAINS_MATCH, form.isCanonicalAutolinkContainsMatch(), username);
        putBool(KEY_CANONICAL_AUTOLINK_VENDOR_UNIQUE_REQUIRED, form.isCanonicalAutolinkVendorUniqueRequired(), username);
        putBool(KEY_CANONICAL_AUTOLINK_PRODUCT_UNIQUE_REQUIRED, form.isCanonicalAutolinkProductUniqueRequired(), username);
        putInt(KEY_CANONICAL_AUTOLINK_MIN_SCORE, clamp(form.getCanonicalAutolinkMinScore(), 0, 1000, 0), username);
        putBool(KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW, form.isCanonicalAutolinkSkipDisabledRow(), username);

        putBool(KEY_CANONICAL_EXPLAIN_SHOW_REASON, form.isCanonicalExplainShowReason(), username);
        putBool(KEY_CANONICAL_EXPLAIN_SHOW_SCORE_BREAKDOWN, form.isCanonicalExplainShowScoreBreakdown(), username);
        putBool(KEY_CANONICAL_EXPLAIN_SHOW_SKIP_REASON, form.isCanonicalExplainShowSkipReason(), username);

        putInt(KEY_VULN_SUGGEST_MAX_ITEMS, clamp(form.getVulnerabilitySuggestionMaxItems(), 1, 100, 20), username);
        putInt(KEY_VULN_SUGGEST_VENDOR_EXACT_SCORE, clamp(form.getVulnerabilitySuggestionVendorExactScore(), 0, 1000, 40), username);
        putInt(KEY_VULN_SUGGEST_VENDOR_PARTIAL_SCORE, clamp(form.getVulnerabilitySuggestionVendorPartialScore(), 0, 1000, 20), username);
        putInt(KEY_VULN_SUGGEST_PRODUCT_EXACT_SCORE, clamp(form.getVulnerabilitySuggestionProductExactScore(), 0, 1000, 50), username);
        putInt(KEY_VULN_SUGGEST_TOKEN_OVERLAP_SCORE, clamp(form.getVulnerabilitySuggestionTokenOverlapScore(), 0, 1000, 25), username);
        putInt(KEY_VULN_SUGGEST_PARTIAL_MATCH_SCORE, clamp(form.getVulnerabilitySuggestionPartialMatchScore(), 0, 1000, 10), username);
        putBool(KEY_VULN_SUGGEST_ACTIVE_ONLY, form.isVulnerabilitySuggestionActiveOnly(), username);
        putBool(KEY_VULN_SUGGEST_SHOW_REASONS, form.isVulnerabilitySuggestionShowReasons(), username);

        putInt(KEY_AUTH_PASSWORD_MIN_LENGTH, clamp(form.getAuthPasswordMinLength(), 8, 256, 8), username);
        putBool(KEY_AUTH_PASSWORD_REQUIRE_UPPER, form.isAuthPasswordRequireUpper(), username);
        putBool(KEY_AUTH_PASSWORD_REQUIRE_LOWER, form.isAuthPasswordRequireLower(), username);
        putBool(KEY_AUTH_PASSWORD_REQUIRE_DIGIT, form.isAuthPasswordRequireDigit(), username);
        putBool(KEY_AUTH_PASSWORD_REQUIRE_SYMBOL, form.isAuthPasswordRequireSymbol(), username);

        ra.addFlashAttribute("success", "Settings updated.");
        return "redirect:/admin/settings";
    }

    @PostMapping("/admin/settings/reset")
    @Transactional
    public String reset(Authentication authentication, RedirectAttributes ra) {
        demoModeService.assertWritable();

        String username = authentication != null ? authentication.getName() : "unknown";

        for (Map.Entry<String, String> e : defaults().entrySet()) {
            put(e.getKey(), e.getValue(), username);
        }

        ra.addFlashAttribute("success", "Settings reset to defaults.");
        return "redirect:/admin/settings";
    }

    private AdminSettingsForm loadForm() {
        AdminSettingsForm f = new AdminSettingsForm();

        f.setCanonicalNormalizeVendorExtractDnOrganization(
                getBool(KEY_CANONICAL_NORMALIZE_VENDOR_EXTRACT_DN_ORGANIZATION, true)
        );
        f.setCanonicalNormalizeVendorRemoveCommonPhrases(
                getBool(KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_COMMON_PHRASES, true)
        );
        f.setCanonicalNormalizeVendorRemoveLegalSuffix(
                getBool(KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_LEGAL_SUFFIX, true)
        );
        f.setCanonicalNormalizeProductRemoveArchParen(
                getBool(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_ARCH_PAREN, true)
        );
        f.setCanonicalNormalizeProductRemoveLocaleTag(
                getBool(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_LOCALE_TAG, true)
        );
        f.setCanonicalNormalizeProductRemoveJavaUpdateSuffix(
                getBool(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_JAVA_UPDATE_SUFFIX, true)
        );
        f.setCanonicalNormalizeProductRemoveVersionSuffix(
                getBool(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_VERSION_SUFFIX, true)
        );

        f.setCanonicalCandidateMinChars(getInt(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2));
        f.setCanonicalCandidateExactLimit(getInt(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5));
        f.setCanonicalCandidateOtherLimit(getInt(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30));
        f.setCanonicalCandidateUnresolvedLimit(getInt(KEY_CANONICAL_CANDIDATE_UNRESOLVED_LIMIT, 20));

        f.setCanonicalAutolinkUseSynonym(getBool(KEY_CANONICAL_AUTOLINK_USE_SYNONYM, true));
        f.setCanonicalAutolinkUseTokenFallback(getBool(KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK, true));
        f.setCanonicalAutolinkContainsMatch(getBool(KEY_CANONICAL_AUTOLINK_CONTAINS_MATCH, false));
        f.setCanonicalAutolinkVendorUniqueRequired(getBool(KEY_CANONICAL_AUTOLINK_VENDOR_UNIQUE_REQUIRED, true));
        f.setCanonicalAutolinkProductUniqueRequired(getBool(KEY_CANONICAL_AUTOLINK_PRODUCT_UNIQUE_REQUIRED, true));
        f.setCanonicalAutolinkMinScore(getInt(KEY_CANONICAL_AUTOLINK_MIN_SCORE, 0));
        f.setCanonicalAutolinkSkipDisabledRow(getBool(KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW, true));

        f.setCanonicalExplainShowReason(getBool(KEY_CANONICAL_EXPLAIN_SHOW_REASON, true));
        f.setCanonicalExplainShowScoreBreakdown(getBool(KEY_CANONICAL_EXPLAIN_SHOW_SCORE_BREAKDOWN, false));
        f.setCanonicalExplainShowSkipReason(getBool(KEY_CANONICAL_EXPLAIN_SHOW_SKIP_REASON, true));

        f.setVulnerabilitySuggestionMaxItems(getInt(KEY_VULN_SUGGEST_MAX_ITEMS, 20));
        f.setVulnerabilitySuggestionVendorExactScore(getInt(KEY_VULN_SUGGEST_VENDOR_EXACT_SCORE, 40));
        f.setVulnerabilitySuggestionVendorPartialScore(getInt(KEY_VULN_SUGGEST_VENDOR_PARTIAL_SCORE, 20));
        f.setVulnerabilitySuggestionProductExactScore(getInt(KEY_VULN_SUGGEST_PRODUCT_EXACT_SCORE, 50));
        f.setVulnerabilitySuggestionTokenOverlapScore(getInt(KEY_VULN_SUGGEST_TOKEN_OVERLAP_SCORE, 25));
        f.setVulnerabilitySuggestionPartialMatchScore(getInt(KEY_VULN_SUGGEST_PARTIAL_MATCH_SCORE, 10));
        f.setVulnerabilitySuggestionActiveOnly(getBool(KEY_VULN_SUGGEST_ACTIVE_ONLY, true));
        f.setVulnerabilitySuggestionShowReasons(getBool(KEY_VULN_SUGGEST_SHOW_REASONS, true));

        f.setAuthPasswordMinLength(getInt(KEY_AUTH_PASSWORD_MIN_LENGTH, 8));
        f.setAuthPasswordRequireUpper(getBool(KEY_AUTH_PASSWORD_REQUIRE_UPPER, false));
        f.setAuthPasswordRequireLower(getBool(KEY_AUTH_PASSWORD_REQUIRE_LOWER, false));
        f.setAuthPasswordRequireDigit(getBool(KEY_AUTH_PASSWORD_REQUIRE_DIGIT, false));
        f.setAuthPasswordRequireSymbol(getBool(KEY_AUTH_PASSWORD_REQUIRE_SYMBOL, false));

        return f;
    }

    private void putMeta(Model model) {
        var latest = systemSettingRepository.findTopByOrderByUpdatedAtDesc();
        model.addAttribute("lastUpdatedAt", latest.map(SystemSetting::getUpdatedAt).orElse(null));
        model.addAttribute("lastUpdatedBy", latest.map(SystemSetting::getUpdatedBy).orElse(null));
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

    private void putInt(String key, int value, String username) {
        put(key, String.valueOf(value), username);
    }

    private void putBool(String key, boolean value, String username) {
        put(key, String.valueOf(value), username);
    }

    private void put(String key, String value, String username) {
        SystemSetting current = systemSettingRepository.findById(key).orElse(null);
        if (current == null) {
            systemSettingRepository.save(SystemSetting.of(key, value, username));
            return;
        }
        current.updateValue(value, username);
        systemSettingRepository.save(current);
    }

    private static int clamp(Integer v, int min, int max, int fallback) {
        int x = (v == null) ? fallback : v;
        if (x < min) return min;
        return Math.min(x, max);
    }

    private static Map<String, String> defaults() {
        Map<String, String> m = new LinkedHashMap<>();

        m.put(KEY_CANONICAL_NORMALIZE_VENDOR_EXTRACT_DN_ORGANIZATION, "true");
        m.put(KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_COMMON_PHRASES, "true");
        m.put(KEY_CANONICAL_NORMALIZE_VENDOR_REMOVE_LEGAL_SUFFIX, "true");
        m.put(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_ARCH_PAREN, "true");
        m.put(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_LOCALE_TAG, "true");
        m.put(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_JAVA_UPDATE_SUFFIX, "true");
        m.put(KEY_CANONICAL_NORMALIZE_PRODUCT_REMOVE_VERSION_SUFFIX, "true");

        m.put(KEY_CANONICAL_CANDIDATE_MIN_CHARS, "2");
        m.put(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, "5");
        m.put(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, "30");
        m.put(KEY_CANONICAL_CANDIDATE_UNRESOLVED_LIMIT, "20");

        m.put(KEY_CANONICAL_AUTOLINK_USE_SYNONYM, "true");
        m.put(KEY_CANONICAL_AUTOLINK_USE_TOKEN_FALLBACK, "true");
        m.put(KEY_CANONICAL_AUTOLINK_CONTAINS_MATCH, "false");
        m.put(KEY_CANONICAL_AUTOLINK_VENDOR_UNIQUE_REQUIRED, "true");
        m.put(KEY_CANONICAL_AUTOLINK_PRODUCT_UNIQUE_REQUIRED, "true");
        m.put(KEY_CANONICAL_AUTOLINK_MIN_SCORE, "0");
        m.put(KEY_CANONICAL_AUTOLINK_SKIP_DISABLED_ROW, "true");

        m.put(KEY_CANONICAL_EXPLAIN_SHOW_REASON, "true");
        m.put(KEY_CANONICAL_EXPLAIN_SHOW_SCORE_BREAKDOWN, "false");
        m.put(KEY_CANONICAL_EXPLAIN_SHOW_SKIP_REASON, "true");

        m.put(KEY_VULN_SUGGEST_MAX_ITEMS, "20");
        m.put(KEY_VULN_SUGGEST_VENDOR_EXACT_SCORE, "40");
        m.put(KEY_VULN_SUGGEST_VENDOR_PARTIAL_SCORE, "20");
        m.put(KEY_VULN_SUGGEST_PRODUCT_EXACT_SCORE, "50");
        m.put(KEY_VULN_SUGGEST_TOKEN_OVERLAP_SCORE, "25");
        m.put(KEY_VULN_SUGGEST_PARTIAL_MATCH_SCORE, "10");
        m.put(KEY_VULN_SUGGEST_ACTIVE_ONLY, "true");
        m.put(KEY_VULN_SUGGEST_SHOW_REASONS, "true");

        m.put(KEY_AUTH_PASSWORD_MIN_LENGTH, "8");
        m.put(KEY_AUTH_PASSWORD_REQUIRE_UPPER, "false");
        m.put(KEY_AUTH_PASSWORD_REQUIRE_LOWER, "false");
        m.put(KEY_AUTH_PASSWORD_REQUIRE_DIGIT, "false");
        m.put(KEY_AUTH_PASSWORD_REQUIRE_SYMBOL, "false");

        return m;
    }
}