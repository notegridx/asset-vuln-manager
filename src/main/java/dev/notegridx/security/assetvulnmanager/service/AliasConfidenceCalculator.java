package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import org.springframework.stereotype.Component;

@Component
public class AliasConfidenceCalculator {

    public int score(AliasSource source, String raw, String canonicalNorm) {
        int base = switch (source) {
            case WINGET -> 88;
            case HOMEBREW -> 86;
            case NPM -> 82;
            case PYPI -> 82;
            case KEV -> 78;
            default -> 60; // Fallback baseline for sources not explicitly defined (e.g., MANUAL)
        };

        int sim = similarity0to100(raw, canonicalNorm); // Range: 0..100
        // Base score is primary, adjusted by similarity (approx. +12 max / -20 min)
        int adjust = (sim - 80) / 2; // sim=80→0, sim=100→+10, sim=40→-20
        int out = base + adjust;

        if (out < 0) out = 0;
        if (out > 100) out = 100;
        return out;
    }

    // Lightweight normalized Levenshtein similarity implementation
    private int similarity0to100(String a, String b) {
        String x = safe(a);
        String y = safe(b);
        if (x.isEmpty() && y.isEmpty()) return 100;
        if (x.isEmpty() || y.isEmpty()) return 0;

        int dist = levenshtein(x, y);
        int max = Math.max(x.length(), y.length());
        double sim = 1.0 - (double) dist / (double) max;
        int s = (int) Math.round(sim * 100.0);
        if (s < 0) s = 0;
        if (s > 100) s = 100;
        return s;
    }

    private String safe(String s) {
        return (s == null) ? "" : s.trim().toLowerCase();
    }

    private int levenshtein(String s1, String s2) {
        int n = s1.length();
        int m = s2.length();
        int[] prev = new int[m + 1];
        int[] curr = new int[m + 1];

        for (int j = 0; j <= m; j++) prev[j] = j;

        for (int i = 1; i <= n; i++) {
            curr[0] = i;
            char c1 = s1.charAt(i - 1);
            for (int j = 1; j <= m; j++) {
                char c2 = s2.charAt(j - 1);
                int cost = (c1 == c2) ? 0 : 1;
                curr[j] = Math.min(
                        Math.min(curr[j - 1] + 1, prev[j] + 1),
                        prev[j - 1] + cost
                );
            }
            int[] tmp = prev; prev = curr; curr = tmp;
        }
        return prev[m];
    }
}