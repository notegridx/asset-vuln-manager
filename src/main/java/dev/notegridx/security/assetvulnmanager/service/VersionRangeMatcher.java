package dev.notegridx.security.assetvulnmanager.service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class VersionRangeMatcher {

    public enum Verdict {
        MATCH,
        NO_MATCH,
        UNKNOWN_VERSION,
        UNPARSABLE_VERSION
    }

    public Verdict verdict(
            String version,
            String startIncluding,
            String startExcluding,
            String endIncluding,
            String endExcluding
    ) {
        String v = normalize(version);
        boolean hasAnyRange =
                normalize(startIncluding) != null ||
                        normalize(startExcluding) != null ||
                        normalize(endIncluding) != null ||
                        normalize(endExcluding) != null;

        // range が無いなら version 不要なので確定
        if (!hasAnyRange) return Verdict.MATCH;

        // range があるのに version が無い：確定できない
        if (v == null) return Verdict.UNKNOWN_VERSION;

        try {
            if (normalize(startIncluding) != null) {
                if (compare(v, startIncluding) < 0) return Verdict.NO_MATCH;
            }
            if (normalize(startExcluding) != null) {
                if (compare(v, startExcluding) <= 0) return Verdict.NO_MATCH;
            }
            if (normalize(endIncluding) != null) {
                if (compare(v, endIncluding) > 0) return Verdict.NO_MATCH;
            }
            if (normalize(endExcluding) != null) {
                if (compare(v, endExcluding) >= 0) return Verdict.NO_MATCH;
            }
            return Verdict.MATCH;
        } catch (Exception e) {
            // 比較不能な version（例: 変な形式、想定外の文字列など）
            return Verdict.UNPARSABLE_VERSION;
        }
    }

    /**
     * 実務向けの簡易比較:
     * - 区切り（., -, _, +, 空白）で分割し、さらに数字/文字の境界でも分割
     * - 数字は数値比較、文字は辞書比較（同位置で数値 > 文字）
     */
    public int compare(String a, String b) {
        String va = Objects.requireNonNull(normalize(a));
        String vb = Objects.requireNonNull(normalize(b));

        List<Token> ta = tokenize(va);
        List<Token> tb = tokenize(vb);

        int n = Math.max(ta.size(), tb.size());
        for (int i = 0; i < n; i++) {
            Token xa = i < ta.size() ? ta.get(i) : Token.zero();
            Token xb = i < tb.size() ? tb.get(i) : Token.zero();
            int c = xa.compareTo(xb);
            if (c != 0) return c;
        }
        return 0;
    }

    private static List<Token> tokenize(String s) {
        String[] rough = s.split("[\\s._\\-+]+");
        List<Token> out = new ArrayList<>();
        for (String part : rough) {
            if (part == null || part.isBlank()) continue;
            out.addAll(splitDigitsLetters(part.trim()));
        }
        return out;
    }

    private static List<Token> splitDigitsLetters(String part) {
        List<Token> out = new ArrayList<>();
        StringBuilder buf = new StringBuilder();
        Boolean digit = null;

        for (int i = 0; i < part.length(); i++) {
            char c = part.charAt(i);
            boolean isDigit = Character.isDigit(c);

            if (digit == null) {
                digit = isDigit;
                buf.append(c);
                continue;
            }

            if (digit == isDigit) {
                buf.append(c);
            } else {
                out.add(Token.of(buf.toString(), digit));
                buf.setLength(0);
                buf.append(c);
                digit = isDigit;
            }
        }
        if (!buf.isEmpty()) out.add(Token.of(buf.toString(), digit != null && digit));
        return out;
    }

    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private sealed interface Token extends Comparable<Token> {
        static Token of(String raw, boolean isDigit) {
            if (raw == null || raw.isBlank()) return zero();
            if (isDigit) {
                try {
                    return new Num(new BigInteger(raw));
                } catch (Exception ignore) {
                    return new Str(raw.toLowerCase());
                }
            }
            return new Str(raw.toLowerCase());
        }

        static Token zero() {
            return new Num(BigInteger.ZERO);
        }
    }

    private record Num(BigInteger n) implements Token {
        @Override
        public int compareTo(Token o) {
            if (o instanceof Num nn) return this.n.compareTo(nn.n);
            // 数値 > 文字
            return 1;
        }
    }

    private record Str(String s) implements Token {
        @Override
        public int compareTo(Token o) {
            if (o instanceof Str ss) return this.s.compareTo(ss.s);
            // 文字 < 数値
            return -1;
        }
    }
}