package dev.notegridx.security.assetvulnmanager.service;

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
}