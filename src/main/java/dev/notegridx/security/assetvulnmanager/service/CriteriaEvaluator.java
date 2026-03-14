package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertMatchMethod;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

@Service
public class CriteriaEvaluator {

    private static final Logger log = LoggerFactory.getLogger(CriteriaEvaluator.class);

    private final VersionRangeMatcher versionMatcher = new VersionRangeMatcher();

    public EvalResult evaluate(
            CriteriaTreeLoader.LoadedCriteriaTree tree,
            List<SoftwareInstall> installs
    ) {
        if (tree == null || !tree.hasRoots() || installs == null || installs.isEmpty()) {
            return EvalResult.noMatch();
        }

        EvalResult best = EvalResult.noMatch();
        Set<String> emittedPredicateSummaries = new HashSet<>();

        for (CriteriaTreeLoader.CriteriaExpr root : tree.roots()) {
            EvalResult r = evaluateExpr(root, installs, emittedPredicateSummaries);
            best = better(best, r);
        }

        return best;
    }

    private EvalResult evaluateExpr(
            CriteriaTreeLoader.CriteriaExpr expr,
            List<SoftwareInstall> installs,
            Set<String> emittedPredicateSummaries
    ) {
        if (expr == null) {
            return EvalResult.noMatch();
        }

        // negate は将来課題。現段階では conservative に false 扱い。
        if (expr.negate()) {
            return EvalResult.noMatch();
        }

        if (expr instanceof CriteriaTreeLoader.CriteriaLeafExpr leaf) {
            return evaluateLeaf(leaf, installs, emittedPredicateSummaries);
        }

        if (expr instanceof CriteriaTreeLoader.CriteriaOperatorExpr op) {
            return evaluateOperator(op, installs, emittedPredicateSummaries);
        }

        return EvalResult.noMatch();
    }

    private EvalResult evaluateOperator(
            CriteriaTreeLoader.CriteriaOperatorExpr op,
            List<SoftwareInstall> installs,
            Set<String> emittedPredicateSummaries
    ) {
        if (op.children() == null || op.children().isEmpty()) {
            return EvalResult.noMatch();
        }

        if (op.operator() == dev.notegridx.security.assetvulnmanager.domain.enums.CriteriaOperator.AND) {
            EvalResult bestPrimary = EvalResult.noMatch();
            boolean anyUnconfirmed = false;
            AlertUncertainReason firstReason = null;
            AlertMatchMethod bestMethod = null;

            for (CriteriaTreeLoader.CriteriaExpr child : op.children()) {
                EvalResult r = evaluateExpr(child, installs, emittedPredicateSummaries);

                logOperatorChildResult(op, r);

                if (!r.matched()) {
                    logOperatorFinalResult(op, EvalResult.noMatch(), "short-circuit-no-match");
                    return EvalResult.noMatch();
                }

                if (r.certainty() == AlertCertainty.UNCONFIRMED) {
                    anyUnconfirmed = true;
                    if (firstReason == null) {
                        firstReason = r.reason();
                    }
                }

                if (bestMethod == null || methodScore(r.method()) > methodScore(bestMethod)) {
                    bestMethod = r.method();
                }

                bestPrimary = better(bestPrimary, r);
            }

            EvalResult finalResult = EvalResult.matched(
                    anyUnconfirmed ? AlertCertainty.UNCONFIRMED : AlertCertainty.CONFIRMED,
                    anyUnconfirmed ? firstReason : null,
                    bestPrimary.primarySoftwareInstallId(),
                    bestMethod
            );

            logOperatorFinalResult(op, finalResult, "and-aggregate");
            return finalResult;
        }

        EvalResult best = EvalResult.noMatch();
        for (CriteriaTreeLoader.CriteriaExpr child : op.children()) {
            EvalResult r = evaluateExpr(child, installs, emittedPredicateSummaries);
            logOperatorChildResult(op, r);
            best = better(best, r);
        }

        logOperatorFinalResult(op, best, "or-aggregate");
        return best;
    }

    private EvalResult evaluateLeaf(
            CriteriaTreeLoader.CriteriaLeafExpr leaf,
            List<SoftwareInstall> installs,
            Set<String> emittedPredicateSummaries
    ) {
        if (leaf.predicates() == null || leaf.predicates().isEmpty()) {
            return EvalResult.noMatch();
        }

        EvalResult best = EvalResult.noMatch();

        for (CriteriaTreeLoader.CriteriaCpePredicate predicate : leaf.predicates()) {
            if (predicate == null || !predicate.matchVulnerable()) {
                continue;
            }

            PredicateCounters counters = new PredicateCounters();

            for (SoftwareInstall si : installs) {
                PredicateEvalOutcome outcome = evaluatePredicate(predicate, si);
                counters.record(outcome);
                best = better(best, outcome.result());
            }

            logPredicateSummary(predicate, counters, emittedPredicateSummaries);
        }

        return best;
    }

    private PredicateEvalOutcome evaluatePredicate(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            SoftwareInstall si
    ) {
        if (predicate == null || si == null) {
            return PredicateEvalOutcome.noMatch(PredicateEvalStatus.SKIPPED_OTHER, EvalResult.noMatch());
        }

        AlertMatchMethod method = resolveIdentityMatch(predicate, si);
        if (method == null) {
            logPredicateSkip(predicate, si, "identity-miss");
            return PredicateEvalOutcome.noMatch(PredicateEvalStatus.IDENTITY_MISS, EvalResult.noMatch());
        }

        if (!isRelevantForAsset(predicate, si.getAsset())) {
            logPredicateSkip(predicate, si, "target-sw-miss");
            return PredicateEvalOutcome.noMatch(PredicateEvalStatus.TARGET_SW_MISS, EvalResult.noMatch());
        }

        String softwareVersion = normalize(si.getVersion());
        if (softwareVersion == null && method == AlertMatchMethod.CPE_NAME) {
            softwareVersion = normalize(extractVersionFromCpe23(si.getCpeName()));
        }

        VersionRangeMatcher.Verdict verdict = versionMatcher.verdict(
                softwareVersion,
                predicate.versionStartIncluding(),
                predicate.versionStartExcluding(),
                predicate.versionEndIncluding(),
                predicate.versionEndExcluding()
        );

        if (verdict == VersionRangeMatcher.Verdict.NO_MATCH) {
            logPredicateVersionEvaluation(
                    predicate,
                    si,
                    method,
                    softwareVersion,
                    verdict,
                    null,
                    null
            );
            return PredicateEvalOutcome.noMatch(PredicateEvalStatus.VERSION_NO_MATCH, EvalResult.noMatch());
        }

        BestVerdict bv = BestVerdict.from(verdict);
        AlertCertainty certainty = bv.toCertainty();
        AlertUncertainReason reason = bv.toReason();

        logPredicateVersionEvaluation(
                predicate,
                si,
                method,
                softwareVersion,
                verdict,
                certainty,
                reason
        );

        EvalResult result = EvalResult.matched(
                certainty,
                reason,
                si.getId(),
                method
        );

        if (certainty == AlertCertainty.UNCONFIRMED) {
            return PredicateEvalOutcome.matched(PredicateEvalStatus.UNCONFIRMED, result);
        }

        return PredicateEvalOutcome.matched(PredicateEvalStatus.MATCH, result);
    }

    private void logPredicateSkip(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            SoftwareInstall si,
            String reason
    ) {
        if (!log.isDebugEnabled()) {
            return;
        }

        if ("identity-miss".equals(reason) && !isVendorNearHit(predicate, si)) {
            return;
        }

        log.debug(
                "criteria-predicate-skip swId={} assetId={} reason={} " +
                        "installVendorNorm='{}' installProductNorm='{}' installCpeName='{}' " +
                        "predicateVendorNorm='{}' predicateProductNorm='{}' predicateCpeName='{}' " +
                        "predicatePart='{}' predicateTargetSw='{}'",
                si != null ? si.getId() : null,
                (si != null && si.getAsset() != null) ? si.getAsset().getId() : null,
                reason,
                si != null ? si.getNormalizedVendor() : null,
                si != null ? si.getNormalizedProduct() : null,
                si != null ? si.getCpeName() : null,
                predicate != null ? predicate.vendorNorm() : null,
                predicate != null ? predicate.productNorm() : null,
                predicate != null ? predicate.cpeName() : null,
                predicate != null ? predicate.cpePart() : null,
                predicate != null ? predicate.targetSw() : null
        );
    }

    private boolean isVendorNearHit(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            SoftwareInstall si
    ) {
        if (predicate == null || si == null) {
            return false;
        }

        String predicateVendorNorm = normalize(predicate.vendorNorm());
        String installVendorNorm = normalize(si.getNormalizedVendor());

        return predicateVendorNorm != null
                && installVendorNorm != null
                && Objects.equals(predicateVendorNorm, installVendorNorm);
    }

    private void logPredicateVersionEvaluation(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            SoftwareInstall si,
            AlertMatchMethod method,
            String softwareVersion,
            VersionRangeMatcher.Verdict verdict,
            AlertCertainty certainty,
            AlertUncertainReason uncertainReason
    ) {
        if (!log.isDebugEnabled()) {
            return;
        }

        log.debug(
                "criteria-version-eval swId={} assetId={} matchedBy={} " +
                        "softwareVersion='{}' installCpeName='{}' " +
                        "predicateCpeName='{}' vendorNorm='{}' productNorm='{}' " +
                        "cpeVendorId={} cpeProductId={} cpePart='{}' targetSw='{}' targetHw='{}' " +
                        "startInc='{}' startExc='{}' endInc='{}' endExc='{}' " +
                        "verdict={} certainty={} uncertainReason={}",
                si != null ? si.getId() : null,
                (si != null && si.getAsset() != null) ? si.getAsset().getId() : null,
                method,
                softwareVersion,
                si != null ? si.getCpeName() : null,
                predicate != null ? predicate.cpeName() : null,
                predicate != null ? predicate.vendorNorm() : null,
                predicate != null ? predicate.productNorm() : null,
                predicate != null ? predicate.cpeVendorId() : null,
                predicate != null ? predicate.cpeProductId() : null,
                predicate != null ? predicate.cpePart() : null,
                predicate != null ? predicate.targetSw() : null,
                predicate != null ? predicate.targetHw() : null,
                predicate != null ? predicate.versionStartIncluding() : null,
                predicate != null ? predicate.versionStartExcluding() : null,
                predicate != null ? predicate.versionEndIncluding() : null,
                predicate != null ? predicate.versionEndExcluding() : null,
                verdict,
                certainty,
                uncertainReason
        );
    }

    private void logPredicateSummary(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            PredicateCounters counters,
            Set<String> emittedPredicateSummaries
    ) {
        if (!counters.hasAnySignal()) {
            return;
        }

        String summaryKey = buildPredicateSummaryKey(predicate, counters);
        if (!emittedPredicateSummaries.add(summaryKey)) {
            return;
        }

        log.info(
                "criteria-predicate-summary vendorNorm='{}' productNorm='{}' " +
                        "targetSw='{}' targetHw='{}' " +
                        "startInc='{}' startExc='{}' endInc='{}' endExc='{}' " +
                        "checked={} identityHits={} targetSwMiss={} noMatch={} unconfirmed={} match={} cpe='{}'",
                predicate != null ? predicate.vendorNorm() : null,
                predicate != null ? predicate.productNorm() : null,
                predicate != null ? predicate.targetSw() : null,
                predicate != null ? predicate.targetHw() : null,
                predicate != null ? predicate.versionStartIncluding() : null,
                predicate != null ? predicate.versionStartExcluding() : null,
                predicate != null ? predicate.versionEndIncluding() : null,
                predicate != null ? predicate.versionEndExcluding() : null,
                counters.checked,
                counters.identityHits,
                counters.targetSwMiss,
                counters.noMatch,
                counters.unconfirmed,
                counters.match,
                predicate != null ? predicate.cpeName() : null
        );
    }

    private String buildPredicateSummaryKey(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            PredicateCounters counters
    ) {
        return String.join("|",
                String.valueOf(predicate != null ? predicate.vendorNorm() : null),
                String.valueOf(predicate != null ? predicate.productNorm() : null),
                String.valueOf(predicate != null ? predicate.targetSw() : null),
                String.valueOf(predicate != null ? predicate.targetHw() : null),
                String.valueOf(predicate != null ? predicate.versionStartIncluding() : null),
                String.valueOf(predicate != null ? predicate.versionStartExcluding() : null),
                String.valueOf(predicate != null ? predicate.versionEndIncluding() : null),
                String.valueOf(predicate != null ? predicate.versionEndExcluding() : null),
                String.valueOf(counters.checked),
                String.valueOf(counters.identityHits),
                String.valueOf(counters.targetSwMiss),
                String.valueOf(counters.noMatch),
                String.valueOf(counters.unconfirmed),
                String.valueOf(counters.match)
        );
    }

    private void logOperatorChildResult(
            CriteriaTreeLoader.CriteriaOperatorExpr op,
            EvalResult childResult
    ) {
        if (!log.isDebugEnabled()) {
            return;
        }

        log.debug(
                "criteria-op-child operator={} negate={} childMatched={} childCertainty={} childReason={} childSwId={} childMethod={}",
                op != null ? op.operator() : null,
                op != null && op.negate(),
                childResult != null && childResult.matched(),
                childResult != null ? childResult.certainty() : null,
                childResult != null ? childResult.reason() : null,
                childResult != null ? childResult.primarySoftwareInstallId() : null,
                childResult != null ? childResult.method() : null
        );
    }

    private void logOperatorFinalResult(
            CriteriaTreeLoader.CriteriaOperatorExpr op,
            EvalResult result,
            String phase
    ) {
        if (!log.isDebugEnabled()) {
            return;
        }

        log.debug(
                "criteria-op-result phase={} operator={} negate={} childCount={} matched={} certainty={} reason={} primarySwId={} method={}",
                phase,
                op != null ? op.operator() : null,
                op != null && op.negate(),
                (op != null && op.children() != null) ? op.children().size() : 0,
                result != null && result.matched(),
                result != null ? result.certainty() : null,
                result != null ? result.reason() : null,
                result != null ? result.primarySoftwareInstallId() : null,
                result != null ? result.method() : null
        );
    }

    private AlertMatchMethod resolveIdentityMatch(
            CriteriaTreeLoader.CriteriaCpePredicate predicate,
            SoftwareInstall si
    ) {
        if (predicate.cpeVendorId() != null
                && predicate.cpeProductId() != null
                && Objects.equals(predicate.cpeVendorId(), si.getCpeVendorId())
                && Objects.equals(predicate.cpeProductId(), si.getCpeProductId())) {
            return AlertMatchMethod.DICT_ID;
        }

        String installVendorNorm = normalize(si.getNormalizedVendor());
        String installProductNorm = normalize(si.getNormalizedProduct());
        if (predicate.vendorNorm() != null
                && predicate.productNorm() != null
                && Objects.equals(predicate.vendorNorm(), installVendorNorm)
                && Objects.equals(predicate.productNorm(), installProductNorm)) {
            return AlertMatchMethod.NORM;
        }

        String installCpeName = normalize(si.getCpeName());
        if (predicate.cpeName() != null
                && installCpeName != null
                && Objects.equals(predicate.cpeName(), installCpeName)) {
            return AlertMatchMethod.CPE_NAME;
        }

        return null;
    }

    private boolean isRelevantForAsset(CriteriaTreeLoader.CriteriaCpePredicate affected, Asset asset) {
        if (affected == null) {
            return false;
        }

        String cpePart = normalizePart(affected.cpePart());
        if (cpePart == null) {
            return false;
        }

        // AVM 当面方針: application CPE のみ対象
        if (!"a".equals(cpePart)) {
            return false;
        }

        String targetSw = normalizeTargetSw(affected.targetSw());

        // wildcard / omitted は共通ビルド扱い
        if (targetSw == null || "*".equals(targetSw) || "-".equals(targetSw)) {
            return true;
        }

        HostOsFamily host = detectHostOsFamily(asset);
        if (host == HostOsFamily.UNKNOWN) {
            return false;
        }

        return switch (host) {
            case WINDOWS -> targetSw.equals("windows");
            case MACOS -> targetSw.equals("mac_os") || targetSw.equals("macos");
            case LINUX -> targetSw.equals("linux");
            default -> false;
        };
    }

    private HostOsFamily detectHostOsFamily(Asset asset) {
        if (asset == null) {
            return HostOsFamily.UNKNOWN;
        }

        String platform = normalize(asset.getPlatform());
        HostOsFamily byPlatform = mapHostOs(platform);
        if (byPlatform != HostOsFamily.UNKNOWN) {
            return byPlatform;
        }

        String osName = normalize(asset.getOsName());
        HostOsFamily byOsName = mapHostOs(osName);
        if (byOsName != HostOsFamily.UNKNOWN) {
            return byOsName;
        }

        String osVersion = normalize(asset.getOsVersion());
        return mapHostOs(osVersion);
    }

    private HostOsFamily mapHostOs(String raw) {
        String s = normalize(raw);
        if (s == null) {
            return HostOsFamily.UNKNOWN;
        }

        String x = s.toLowerCase(Locale.ROOT);

        if (x.contains("win")) {
            return HostOsFamily.WINDOWS;
        }
        if (x.equals("darwin")
                || x.contains("mac")
                || x.contains("os x")
                || x.contains("osx")) {
            return HostOsFamily.MACOS;
        }
        if (x.contains("linux")
                || x.contains("ubuntu")
                || x.contains("debian")
                || x.contains("rhel")
                || x.contains("red hat")
                || x.contains("centos")
                || x.contains("rocky")
                || x.contains("alma")
                || x.contains("suse")
                || x.contains("fedora")
                || x.contains("amazon linux")) {
            return HostOsFamily.LINUX;
        }

        return HostOsFamily.UNKNOWN;
    }

    private static EvalResult better(EvalResult a, EvalResult b) {
        if (score(b) > score(a)) {
            return b;
        }
        if (score(b) < score(a)) {
            return a;
        }

        if (methodScore(b.method()) > methodScore(a.method())) {
            return b;
        }
        if (methodScore(b.method()) < methodScore(a.method())) {
            return a;
        }

        Long aId = a.primarySoftwareInstallId();
        Long bId = b.primarySoftwareInstallId();

        if (aId == null) return b;
        if (bId == null) return a;

        return (bId < aId) ? b : a;
    }

    private static int score(EvalResult r) {
        if (r == null || !r.matched()) return 0;
        if (r.certainty() == AlertCertainty.CONFIRMED) return 2;
        return 1;
    }

    private static int methodScore(AlertMatchMethod method) {
        if (method == AlertMatchMethod.DICT_ID) return 3;
        if (method == AlertMatchMethod.NORM) return 2;
        if (method == AlertMatchMethod.CPE_NAME) return 1;
        return 0;
    }

    private static String normalizePart(String raw) {
        String s = normalize(raw);
        if (s == null) {
            return null;
        }

        String x = s.toLowerCase(Locale.ROOT);
        return switch (x) {
            case "a", "o", "h" -> x;
            default -> x;
        };
    }

    private static String normalizeTargetSw(String raw) {
        String s = normalize(raw);
        if (s == null) {
            return null;
        }

        String x = s.toLowerCase(Locale.ROOT);

        return switch (x) {
            case "windows", "microsoft_windows" -> "windows";
            case "mac_os", "macos", "mac_os_x", "darwin" -> "mac_os";
            case "linux", "gnu_linux" -> "linux";
            case "iphone_os", "ios", "ipad_os", "android" -> x;
            case "*", "-" -> x;
            default -> x;
        };
    }

    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    /**
     * cpe:2.3:a:vendor:product:version:update:... の version を抜く。
     */
    private static String extractVersionFromCpe23(String cpe23) {
        if (cpe23 == null) return null;

        String s = cpe23.trim();
        if (s.isEmpty()) return null;

        String[] parts = s.split(":", -1);
        if (parts.length < 6) return null;
        if (!"cpe".equalsIgnoreCase(parts[0])) return null;
        if (!"2.3".equalsIgnoreCase(parts[1])) return null;

        String version = parts[5];
        if (version == null) return null;

        String v = version.trim();
        if (v.isEmpty() || "*".equals(v) || "-".equals(v)) {
            return null;
        }

        return v;
    }

    public record EvalResult(
            boolean matched,
            AlertCertainty certainty,
            AlertUncertainReason reason,
            Long primarySoftwareInstallId,
            AlertMatchMethod method
    ) {
        public static EvalResult noMatch() {
            return new EvalResult(false, null, null, null, null);
        }

        public static EvalResult matched(
                AlertCertainty certainty,
                AlertUncertainReason reason,
                Long primarySoftwareInstallId,
                AlertMatchMethod method
        ) {
            return new EvalResult(true, certainty, reason, primarySoftwareInstallId, method);
        }
    }

    private enum HostOsFamily {
        WINDOWS,
        MACOS,
        LINUX,
        UNKNOWN
    }

    private enum PredicateEvalStatus {
        IDENTITY_MISS,
        TARGET_SW_MISS,
        VERSION_NO_MATCH,
        UNCONFIRMED,
        MATCH,
        SKIPPED_OTHER
    }

    private record PredicateEvalOutcome(
            PredicateEvalStatus status,
            EvalResult result
    ) {
        static PredicateEvalOutcome noMatch(PredicateEvalStatus status, EvalResult result) {
            return new PredicateEvalOutcome(status, result);
        }

        static PredicateEvalOutcome matched(PredicateEvalStatus status, EvalResult result) {
            return new PredicateEvalOutcome(status, result);
        }
    }

    private static final class PredicateCounters {
        int checked;
        int identityHits;
        int targetSwMiss;
        int noMatch;
        int unconfirmed;
        int match;

        void record(PredicateEvalOutcome outcome) {
            checked++;

            if (outcome == null || outcome.status() == null) {
                return;
            }

            switch (outcome.status()) {
                case IDENTITY_MISS -> {
                    // no-op
                }
                case TARGET_SW_MISS -> {
                    identityHits++;
                    targetSwMiss++;
                }
                case VERSION_NO_MATCH -> {
                    identityHits++;
                    noMatch++;
                }
                case UNCONFIRMED -> {
                    identityHits++;
                    unconfirmed++;
                }
                case MATCH -> {
                    identityHits++;
                    match++;
                }
                case SKIPPED_OTHER -> {
                    // no-op
                }
            }
        }

        boolean hasAnySignal() {
            return identityHits > 0
                    || targetSwMiss > 0
                    || noMatch > 0
                    || unconfirmed > 0
                    || match > 0;
        }
    }

    private static final class BestVerdict {
        private static final EnumSet<VersionRangeMatcher.Verdict> UNCONFIRMED =
                EnumSet.of(
                        VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT,
                        VersionRangeMatcher.Verdict.UNKNOWN_VERSION,
                        VersionRangeMatcher.Verdict.UNPARSABLE_VERSION
                );

        private final VersionRangeMatcher.Verdict verdict;

        private BestVerdict(VersionRangeMatcher.Verdict verdict) {
            this.verdict = verdict;
        }

        static BestVerdict from(VersionRangeMatcher.Verdict v) {
            return new BestVerdict(v == null ? VersionRangeMatcher.Verdict.NO_MATCH : v);
        }

        AlertCertainty toCertainty() {
            if (verdict == VersionRangeMatcher.Verdict.MATCH) return AlertCertainty.CONFIRMED;
            if (UNCONFIRMED.contains(verdict)) return AlertCertainty.UNCONFIRMED;
            return AlertCertainty.CONFIRMED;
        }

        AlertUncertainReason toReason() {
            if (verdict == VersionRangeMatcher.Verdict.NO_VERSION_CONSTRAINT) return AlertUncertainReason.NO_VERSION_CONSTRAINT;
            if (verdict == VersionRangeMatcher.Verdict.UNKNOWN_VERSION) return AlertUncertainReason.MISSING_SOFTWARE_VERSION;
            if (verdict == VersionRangeMatcher.Verdict.UNPARSABLE_VERSION) return AlertUncertainReason.UNPARSABLE_SOFTWARE_VERSION;
            return null;
        }
    }
}