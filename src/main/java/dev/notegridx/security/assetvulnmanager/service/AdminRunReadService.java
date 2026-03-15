package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
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
     * Parses JSON into a "friendly map" for kv-pills.
     *
     * Rules:
     * - If JSON is an object: return key->value (scalar as String, complex as compact JSON string)
     * - If JSON is non-object (array/scalar): store it under "_raw"
     * - On parse error: store raw under "_raw" and error under "_parseError"
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

            // non-object JSON -> keep as raw
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
        if (v == null) {
            return "null";
        }
        if (v instanceof String s) {
            return s;
        }
        if (v instanceof Number n) {
            return n.toString();
        }
        if (v instanceof Boolean b) {
            return b.toString();
        }

        // For nested object/array, render as compact JSON string so it still fits in a pill.
        try {
            return objectMapper.writeValueAsString(v);
        } catch (Exception ignore) {
            return String.valueOf(v);
        }
    }
}