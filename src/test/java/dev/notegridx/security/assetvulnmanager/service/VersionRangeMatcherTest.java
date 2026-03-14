package dev.notegridx.security.assetvulnmanager.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VersionRangeMatcherTest {

    private final VersionRangeMatcher matcher = new VersionRangeMatcher();

    @Test
    void verdict_returnsNoVersionConstraint_whenNoRangeIsGiven() {
        assertThat(matcher.verdict("1.2.3", null, null, null, null))
                .isEqualTo(VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT);

        assertThat(matcher.verdict("1.2.3", "", "", "", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT);
    }

    @Test
    void verdict_returnsUnknownVersion_whenRangeExistsButSoftwareVersionIsBlank() {
        assertThat(matcher.verdict(null, "1.0", null, "2.0", null))
                .isEqualTo(VersionRangeMatcher.Verdict.UNKNOWN_VERSION);

        assertThat(matcher.verdict("   ", "1.0", null, "2.0", null))
                .isEqualTo(VersionRangeMatcher.Verdict.UNKNOWN_VERSION);
    }

    @Test
    void verdict_matches_whenVersionFallsWithinInclusiveRange() {
        assertThat(matcher.verdict("1.5.0", "1.0.0", null, "2.0.0", null))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);

        assertThat(matcher.verdict("1.0.0", "1.0.0", null, "2.0.0", null))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);

        assertThat(matcher.verdict("2.0.0", "1.0.0", null, "2.0.0", null))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    void verdict_respectsExclusiveBounds() {
        assertThat(matcher.verdict("1.0.0", null, "1.0.0", null, "2.0.0"))
                .isEqualTo(VersionRangeMatcher.Verdict.NO_MATCH);

        assertThat(matcher.verdict("2.0.0", null, "1.0.0", null, "2.0.0"))
                .isEqualTo(VersionRangeMatcher.Verdict.NO_MATCH);

        assertThat(matcher.verdict("1.5.0", null, "1.0.0", null, "2.0.0"))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    void compare_handlesNumericSegmentsNaturally() {
        assertThat(matcher.compare("1.10", "1.2")).isGreaterThan(0);
        assertThat(matcher.compare("2.0", "10.0")).isLessThan(0);
        assertThat(matcher.compare("1.0.0", "1")).isEqualTo(0);
    }

    @Test
    void compare_splitsDigitAndLetterBoundaries() {
        assertThat(matcher.compare("1.0a", "1.0")).isLessThan(0);
        assertThat(matcher.compare("1.0b", "1.0a")).isGreaterThan(0);
        assertThat(matcher.compare("2024r2", "2024r10")).isLessThan(0);
    }

    @Test
    void compare_treatsNumberTokenAsGreaterThanStringToken() {
        assertThat(matcher.compare("1.0.1", "1.0.a")).isGreaterThan(0);
        assertThat(matcher.compare("1.0.a", "1.0.1")).isLessThan(0);
    }

    @Test
    @DisplayName("compare treats leading v prefix as equivalent")
    void compare_vPrefix_isIgnored() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("v1.2.3", "1.2.3")).isZero();
        assertThat(m.compare("V1.2.3", "1.2.3")).isZero();
    }

    @Test
    @DisplayName("compare treats underscore as dot separator")
    void compare_underscoreSeparator_isEquivalentToDot() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("1_2_3", "1.2.3")).isZero();
    }

    @Test
    @DisplayName("compare treats hyphen as dot separator for numeric segments")
    void compare_hyphenSeparator_isEquivalentToDot() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("1-2-3", "1.2.3")).isZero();
    }

    @Test
    @DisplayName("compare ignores leading zeros in numeric tokens")
    void compare_leadingZeros_areIgnored() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("01.002.0003", "1.2.3")).isZero();
        assertThat(m.compare("0001.0000", "1.0")).isZero();
    }

    @Test
    @DisplayName("compare treats trailing numeric zeros as equal")
    void compare_trailingZeros_areIgnored() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("1.0.0", "1")).isZero();
        assertThat(m.compare("1.0.0.0", "1")).isZero();
        assertThat(m.compare("1.2.0.0", "1.2")).isZero();
    }

    @Test
    @DisplayName("compare keeps significance when trailing segment is non-zero")
    void compare_nonZeroTrailingSegment_remainsSignificant() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("1.0.0.1", "1")).isGreaterThan(0);
        assertThat(m.compare("1", "1.0.0.1")).isLessThan(0);
    }

    @Test
    @DisplayName("compare trims surrounding spaces before comparison")
    void compare_surroundingSpaces_areIgnored() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("  1.2.3  ", "1.2.3")).isZero();
    }

    @Test
    @DisplayName("compare treats calendar-like zero padded numbers as equal")
    void compare_zeroPaddedCalendarVersion_isEqual() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.compare("2024.01", "2024.1")).isZero();
    }

    @Test
    @DisplayName("verdict matches when version has v prefix")
    void verdict_matches_whenVersionHasVPrefix() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.verdict("v1.5.0", "1.0.0", "", "2.0.0", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    @DisplayName("verdict matches when version uses underscore separators")
    void verdict_matches_whenVersionUsesUnderscoreSeparators() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.verdict("1_5_0", "1.0.0", "", "2.0.0", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    @DisplayName("verdict matches when version uses hyphen separators")
    void verdict_matches_whenVersionUsesHyphenSeparators() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.verdict("1-5-0", "1.0.0", "", "2.0.0", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    @DisplayName("verdict matches when numeric tokens contain leading zeros")
    void verdict_matches_whenNumericTokensContainLeadingZeros() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.verdict("01.005.000", "1.0.0", "", "2.0.0", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    @DisplayName("verdict matches when trailing zeros are present in software version")
    void verdict_matches_whenTrailingZerosArePresent() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.verdict("1.5.0.0", "1.0", "", "2.0", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.MATCH);
    }

    @Test
    @DisplayName("verdict does not match when non-zero trailing segment exceeds upper bound")
    void verdict_noMatch_whenNonZeroTrailingSegmentExceedsUpperBound() {
        VersionRangeMatcher m = new VersionRangeMatcher();

        assertThat(m.verdict("2.0.0.1", "1.0", "", "2.0", ""))
                .isEqualTo(VersionRangeMatcher.Verdict.NO_MATCH);
    }
}