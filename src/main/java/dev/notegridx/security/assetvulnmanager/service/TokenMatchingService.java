package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

@Service
public class TokenMatchingService {

    private static final Pattern UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern MOSTLY_VERSION = Pattern.compile("^[0-9]+(\\.[0-9]+){1,4}$");
    private static final Set<String> STOP = Set.of(
            "microsoft", "corporation", "inc", "ltd", "llc",
            "windows", "microsoft.", // publisher汚れ対策
            "x64", "x86", "arm64",
            "minimum", "additional",
            "runtime", "redistributable",
            "update", "installer", "package"
    );

    private final CpeProductRepository productRepo;

    public TokenMatchingService(CpeProductRepository productRepo) {
        this.productRepo = productRepo;
    }

    public Optional<CpeProduct> bestProduct(Long vendorId, String productNorm) {
        if (vendorId == null) return Optional.empty();
        if (productNorm == null || productNorm.isBlank()) return Optional.empty();

        String p = productNorm.trim().toLowerCase(Locale.ROOT);

        // Windows store / UWP のGUIDやパッケージっぽいものは除外
        if (UUID.matcher(p).matches()) return Optional.empty();
        if (p.contains(".") && !p.contains(" ")) {
            // e.g. Microsoft.AAD.BrokerPlugin / Clipchamp.Clipchamp
            return Optional.empty();
        }

        List<String> tokens = tokens(p);
        if (tokens.isEmpty()) return Optional.empty();

        // 代表トークン：長い順に最大3つ
        List<String> keyTokens = tokens.stream()
                .filter(t -> t.length() >= 3)
                .filter(t -> !STOP.contains(t))
                .filter(t -> !MOSTLY_VERSION.matcher(t).matches())
                .sorted(Comparator.comparingInt(String::length).reversed())
                .limit(3)
                .toList();

        if (keyTokens.isEmpty()) return Optional.empty();

        // 候補収集：まず一番強いトークンで contains 検索
        List<CpeProduct> cands = productRepo
                .findTop200ByVendorIdAndNameNormContainingOrderByNameNormAsc(vendorId, keyTokens.get(0));

        if (cands.isEmpty()) return Optional.empty();

        // スコアリング（単純だが効く）
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

        // 閾値 + 2位との差（誤爆防止）
        int minScore = 6; // overlap 2 くらいは欲しい
        int margin = 2;

        if (best.score < minScore) return Optional.empty();
        if (second != null && (best.score - second.score) < margin) return Optional.empty();

        return Optional.of(best.product);
    }

    private static String safe(String s) {
        if (s == null) return null;
        String t = s.trim().toLowerCase(Locale.ROOT);
        return t.isEmpty() ? null : t;
    }

    private static List<String> tokens(String s) {
        // 許容文字は normalizer に寄せる前提。ここでは分割のみ。
        String x = s.replaceAll("[^a-z0-9\\+._\\- ]", " ");
        x = x.replaceAll("[._\\-\\+]", " ");
        x = x.replaceAll("\\s+", " ").trim();
        if (x.isEmpty()) return List.of();
        return Arrays.asList(x.split(" "));
    }

    private record Scored(CpeProduct product, int score) {}
}