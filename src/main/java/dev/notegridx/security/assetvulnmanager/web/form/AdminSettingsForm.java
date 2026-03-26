package dev.notegridx.security.assetvulnmanager.web.form;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AdminSettingsForm {

    // ------------------------------------------------------------
    // Canonical Mapping > Normalize policy
    // ------------------------------------------------------------
    private boolean canonicalNormalizeVendorExtractDnOrganization;
    private boolean canonicalNormalizeVendorRemoveCommonPhrases;
    private boolean canonicalNormalizeVendorRemoveLegalSuffix;
    private boolean canonicalNormalizeProductRemoveArchParen;
    private boolean canonicalNormalizeProductRemoveLocaleTag;
    private boolean canonicalNormalizeProductRemoveJavaUpdateSuffix;
    private boolean canonicalNormalizeProductRemoveVersionSuffix;

    // ------------------------------------------------------------
    // Canonical Mapping > Candidate display
    // ------------------------------------------------------------
    private Integer canonicalCandidateMinChars;
    private Integer canonicalCandidateExactLimit;
    private Integer canonicalCandidateOtherLimit;
    private Integer canonicalCandidateUnresolvedLimit;

    // ------------------------------------------------------------
    // Canonical Mapping > Auto-link policy
    // ------------------------------------------------------------
    private boolean canonicalAutolinkUseSynonym;
    private boolean canonicalAutolinkUseTokenFallback;
    private boolean canonicalAutolinkContainsMatch;
    private boolean canonicalAutolinkVendorUniqueRequired;
    private boolean canonicalAutolinkProductUniqueRequired;
    private Integer canonicalAutolinkMinScore;
    private boolean canonicalAutolinkSkipDisabledRow;

    // ------------------------------------------------------------
    // Canonical Mapping > Explainability
    // ------------------------------------------------------------
    private boolean canonicalExplainShowReason;
    private boolean canonicalExplainShowScoreBreakdown;
    private boolean canonicalExplainShowSkipReason;

    // ------------------------------------------------------------
    // Vulnerability Suggestions
    // ------------------------------------------------------------
    private Integer vulnerabilitySuggestionMaxItems;
    private Integer vulnerabilitySuggestionVendorExactScore;
    private Integer vulnerabilitySuggestionVendorPartialScore;
    private Integer vulnerabilitySuggestionProductExactScore;
    private Integer vulnerabilitySuggestionTokenOverlapScore;
    private Integer vulnerabilitySuggestionPartialMatchScore;
    private boolean vulnerabilitySuggestionActiveOnly;
    private boolean vulnerabilitySuggestionShowReasons;

    // ------------------------------------------------------------
    // Authentication > Account lock
    // ------------------------------------------------------------
    private boolean authAccountLockEnabled;
    private Integer authMaxFailedLogins;

    // ------------------------------------------------------------
    // Authentication > Password policy
    // ------------------------------------------------------------
    private Integer authPasswordMinLength;
    private boolean authPasswordRequireUpper;
    private boolean authPasswordRequireLower;
    private boolean authPasswordRequireDigit;
    private boolean authPasswordRequireSymbol;
}