package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminRunStatus;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class AdminRunReadService {

    public enum ParseErrorStyle {
        SIMPLE_CLASS_NAME,
        MESSAGE_AND_RAW
    }

    public record LastRunView(
            AdminRun run,
            Map<String, Object> params,
            Map<String, Object> result
    ) {}

    public record AdminRunRow(
            AdminRun run,
            Map<String, Object> params,
            Map<String, Object> result
    ) {}

    private final AdminRunRepository adminRunRepository;
    private final ObjectMapper objectMapper;

    public AdminRunReadService(
            AdminRunRepository adminRunRepository,
            ObjectMapper objectMapper
    ) {
        this.adminRunRepository = adminRunRepository;
        this.objectMapper = objectMapper;
    }

    public LastRunView findLastRun(AdminJobType jobType, ParseErrorStyle parseErrorStyle) {
        Optional<AdminRun> opt = adminRunRepository
                .findTop1ByJobTypeOrderByStartedAtDescIdDesc(jobType);

        if (opt.isEmpty()) {
            return null;
        }

        AdminRun run = opt.get();
        return new LastRunView(
                run,
                parseJsonToMap(run.getParamsJson(), parseErrorStyle),
                parseJsonToMap(run.getResultJson(), parseErrorStyle)
        );
    }

    public void bindLastRun(
            Model model,
            AdminJobType jobType,
            ParseErrorStyle parseErrorStyle
    ) {
        LastRunView last = findLastRun(jobType, parseErrorStyle);

        if (last == null) {
            model.addAttribute("lastRun", null);
            model.addAttribute("lastParams", null);
            model.addAttribute("lastResult", null);
            return;
        }

        model.addAttribute("lastRun", last.run());
        model.addAttribute("lastParams", last.params());
        model.addAttribute("lastResult", last.result());
    }

    public List<AdminRunRow> findRecentRuns(int limit) {
        int safeLimit = Math.max(1, limit);

        return adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc().stream()
                .limit(safeLimit)
                .map(run -> new AdminRunRow(
                        run,
                        parseJsonToFriendlyMap(run.getParamsJson()),
                        parseJsonToFriendlyMap(run.getResultJson())
                ))
                .toList();
    }

    public Page<AdminRunRow> searchRuns(
            String jobType,
            String status,
            String q,
            int page,
            int size
    ) {
        int safePage = Math.max(page, 0);
        int safeSize = Math.max(size, 1);

        AdminJobType jobTypeEnum = parseJobType(jobType);
        AdminRunStatus statusEnum = parseStatus(status);
        String normalizedQ = normalize(q);

        Pageable pageable = PageRequest.of(
                safePage,
                safeSize,
                Sort.by(Sort.Order.desc("startedAt"), Sort.Order.desc("id"))
        );

        Page<AdminRun> basePage = findBasePage(jobTypeEnum, statusEnum, pageable);

        if (normalizedQ == null) {
            return basePage.map(run -> new AdminRunRow(
                    run,
                    parseJsonToFriendlyMap(run.getParamsJson()),
                    parseJsonToFriendlyMap(run.getResultJson())
            ));
        }

        List<AdminRunRow> filteredRows = basePage.getContent().stream()
                .filter(run -> matchesQ(run, normalizedQ))
                .map(run -> new AdminRunRow(
                        run,
                        parseJsonToFriendlyMap(run.getParamsJson()),
                        parseJsonToFriendlyMap(run.getResultJson())
                ))
                .toList();

        return new PageImpl<>(filteredRows, pageable, filteredRows.size());
    }

    private Page<AdminRun> findBasePage(
            AdminJobType jobType,
            AdminRunStatus status,
            Pageable pageable
    ) {
        if (jobType != null && status != null) {
            return adminRunRepository.findByJobTypeAndStatusOrderByStartedAtDescIdDesc(jobType, status, pageable);
        }
        if (jobType != null) {
            return adminRunRepository.findByJobTypeOrderByStartedAtDescIdDesc(jobType, pageable);
        }
        if (status != null) {
            return adminRunRepository.findByStatusOrderByStartedAtDescIdDesc(status, pageable);
        }
        return adminRunRepository.findAllByOrderByStartedAtDescIdDesc(pageable);
    }

    private boolean matchesQ(AdminRun run, String q) {
        String needle = q.toLowerCase(Locale.ROOT);

        return containsIgnoreCase(run.getParamsJson(), needle)
                || containsIgnoreCase(run.getResultJson(), needle)
                || containsIgnoreCase(run.getErrorMessage(), needle)
                || (run.getJobType() != null && run.getJobType().name().toLowerCase(Locale.ROOT).contains(needle))
                || (run.getStatus() != null && run.getStatus().name().toLowerCase(Locale.ROOT).contains(needle));
    }

    private boolean containsIgnoreCase(String value, String needleLower) {
        return value != null && value.toLowerCase(Locale.ROOT).contains(needleLower);
    }

    private AdminJobType parseJobType(String value) {
        String normalized = normalize(value);
        if (normalized == null) {
            return null;
        }

        try {
            return AdminJobType.valueOf(normalized.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private AdminRunStatus parseStatus(String value) {
        String normalized = normalize(value);
        if (normalized == null) {
            return null;
        }

        try {
            return AdminRunStatus.valueOf(normalized.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private String normalize(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private Map<String, Object> parseJsonToMap(String json, ParseErrorStyle parseErrorStyle) {
        if (json == null || json.isBlank()) {
            return null;
        }

        try {
            return objectMapper.readValue(
                    json,
                    new TypeReference<LinkedHashMap<String, Object>>() {}
            );
        } catch (Exception e) {
            Map<String, Object> m = new LinkedHashMap<>();

            if (parseErrorStyle == ParseErrorStyle.MESSAGE_AND_RAW) {
                m.put("_parseError", e.getMessage());
                m.put("_raw", json);
            } else {
                m.put("_parseError", e.getClass().getSimpleName());
            }

            return m;
        }
    }

    /**
     * Parses JSON into a friendly key-value map for UI display.
     *
     * Rules:
     * - If JSON is an object: return key -> friendly value
     * - If JSON is non-object: return {_raw=...}
     * - On parse error: return {_raw=..., _parseError=...}
     */
    private Map<String, Object> parseJsonToFriendlyMap(String json) {
        if (json == null || json.isBlank()) {
            return null;
        }

        String raw = json.trim();

        try {
            Object parsed = objectMapper.readValue(raw, Object.class);

            if (parsed instanceof Map<?, ?> m) {
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if (e.getKey() == null) {
                        continue;
                    }

                    String k = String.valueOf(e.getKey());
                    Object v = e.getValue();
                    out.put(k, friendlyValue(v));
                }
                return out.isEmpty() ? null : out;
            }

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("_raw", raw);
            return out;

        } catch (Exception ex) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("_raw", raw);
            out.put("_parseError", ex.getMessage());
            return out;
        }
    }

    private Object friendlyValue(Object v) {
        if (v == null) return "null";
        if (v instanceof String s) return s;
        if (v instanceof Number n) return n.toString();
        if (v instanceof Boolean b) return b.toString();

        try {
            return objectMapper.writeValueAsString(v);
        } catch (Exception ignore) {
            return String.valueOf(v);
        }
    }
}