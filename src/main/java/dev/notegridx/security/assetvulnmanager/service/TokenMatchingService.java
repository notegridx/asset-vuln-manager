package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Provides a conservative token-based fallback when exact product lookup fails.
 *
 * <p>This service is intentionally a last-resort matcher. It is designed to
 * recover common naming drift after normalization and synonym resolution, while
 * rejecting ambiguous inputs that are likely to produce false positives.
 *
 * <p>Matching is always vendor-scoped. This keeps generic product tokens from
 * drifting across vendors during canonical linking.
 */
@Service
public class TokenMatchingService {

    private static final Pattern UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern MOSTLY_VERSION = Pattern.compile("^[0-9]+(\\.[0-9]+){1,4}$");
    private static final Set<String> STOP = Set.of(
            "microsoft", "corporation", "inc", "ltd", "llc",
            "windows", "microsoft.", // NOTE: absorbs publisher noise that often leaks into product-like strings
            "x64", "x86", "arm64",
            "minimum", "additional",
            "runtime", "redistributable",
            "update", "installer", "package"
    );

    private final CpeProductRepository productRepo;

    public TokenMatchingService(CpeProductRepository productRepo) {
        this.productRepo = productRepo;
    }

    /**
     * Returns the best vendor-scoped product candidate for a normalized product string.
     *
     * <p>This method favors precision over recall. It refuses to match when the
     * input looks identifier-like, when useful tokens cannot be extracted, or
     * when the top candidates are too close to separate confidently.
     */
    public Optional<CpeProduct> bestProduct(Long vendorId, String productNorm) {
        if (vendorId == null) return Optional.empty();
        if (productNorm == null || productNorm.isBlank()) return Optional.empty();

        String p = productNorm.trim().toLowerCase(Locale.ROOT);

        // NOTE: Windows Store / AppX-style identifiers often look searchable but
        // are poor canonical product keys and tend to create false matches.
        if (UUID.matcher(p).matches()) return Optional.empty();
        if (p.contains(".") && !p.contains(" ")) {
            // e.g. Microsoft.AAD.BrokerPlugin / Clipchamp.Clipchamp
            return Optional.empty();
        }

        List<String> tokens = tokens(p);
        if (tokens.isEmpty()) return Optional.empty();

        // Use a few strong tokens to keep candidate collection cheap and
        // targeted before scoring the broader token overlap.
        List<String> keyTokens = tokens.stream()
                .filter(t -> t.length() >= 3)
                .filter(t -> !STOP.contains(t))
                .filter(t -> !MOSTLY_VERSION.matcher(t).matches())
                .sorted(Comparator.comparingInt(String::length).reversed())
                .limit(3)
                .toList();

        if (keyTokens.isEmpty()) return Optional.empty();

        // Start with the strongest token so later scoring works on a small,
        // plausibly relevant vendor-scoped candidate set.
        List<CpeProduct> cands = productRepo
                .findTop200ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendorId, keyTokens.get(0));

        if (cands.isEmpty()) return Optional.empty();

        // NOTE: The scoring model is intentionally simple. The goal is not to
        // find the most "similar" string in general, but to separate clearly
        // better candidates from the rest with predictable behavior.
        Scored best = null;
        Scored second = null;

        Set<String> tokenSet = new HashSet<>(tokens);

        for (CpeProduct cp : cands) {
            String name = safe(cp.getNameNorm());
            if (name == null) continue;

            Set<String> cpt = new HashSet<>(tokens(name));

            int overlap = 0;
            for (String t : tokenSet) if (cpt.contains(t)) overlap++;

            int bonusPrefix = name.startsWith(p) ? 3 : 0;
            int penaltyLen = Math.max(0, (name.length() - p.length()) / 20);

            int score = overlap * 3 + bonusPrefix - penaltyLen;

            if (best == null || score > best.score) {
                second = best;
                best = new Scored(cp, score);
            } else if (second == null || score > second.score) {
                second = new Scored(cp, score);
            }
        }

        if (best == null) return Optional.empty();

        // Require both a minimum quality bar and clear separation from the
        // runner-up so fuzzy matching does not auto-link marginal guesses.
        int minScore = 6; // overlap around 2 is the minimum acceptable signal
        int margin = 2;

        if (best.score < minScore) return Optional.empty();
        if (second != null && (best.score - second.score) < margin) return Optional.empty();

        return Optional.of(best.product);
    }

    /**
     * Normalizes local comparison input for token scoring.
     *
     * <p>This does not replace the main normalizer. It only keeps internal
     * scoring behavior stable when repository values include casing noise.
     */
    private static String safe(String s) {
        if (s == null) return null;
        String t = s.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }

    /**
     * Splits a normalized product string into comparable tokens.
     *
     * <p>This tokenizer is intentionally lightweight. It assumes upstream
     * normalization already handled the main cleanup policy and focuses only on
     * producing stable token boundaries for overlap scoring.
     */
    private static List<String> tokens(String s) {
        String x = s.replaceAll("[^a-z0-9\\+._\\- ]", " ");
        x = x.replaceAll("[._\\-\\+]", " ");
        x = x.replaceAll("\\s+", " ").trim();
        if (x.isEmpty()) return List.of();
        return Arrays.asList(x.split(" "));
    }

    private record Scored(CpeProduct product, int score) {}
}