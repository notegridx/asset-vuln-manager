package dev.notegridx.security.assetvulnmanager.web;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Controller
public class AdminRunController {

    private final AdminRunRepository adminRunRepository;
    private final ObjectMapper objectMapper;

    public AdminRunController(AdminRunRepository adminRunRepository, ObjectMapper objectMapper) {
        this.adminRunRepository = adminRunRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * View model: AdminRun + parsed params/result maps.
     * (Avoids mutating entity / adding transient fields.)
     */
    public record AdminRunView(
            AdminRun run,
            Map<String, Object> params,
            Map<String, Object> result
    ) {}

    @GetMapping("/admin/runs")
    public String runs(Model model) {
        List<AdminRun> runs = adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc();

        List<AdminRunView> rows = runs.stream()
                .map(r -> new AdminRunView(
                        r,
                        parseJsonToFriendlyMap(r.getParamsJson()),
                        parseJsonToFriendlyMap(r.getResultJson())
                ))
                .toList();

        model.addAttribute("runs", rows);
        return "admin/runs";
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
        if (json == null || json.isBlank()) return null;

        String raw = json.trim();

        try {
            Object parsed = objectMapper.readValue(raw, Object.class);

            if (parsed instanceof Map<?, ?> m) {
                Map<String, Object> out = new LinkedHashMap<>();
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if (e.getKey() == null) continue;
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
        if (v == null) return "null";
        if (v instanceof String s) return s;
        if (v instanceof Number n) return n.toString();
        if (v instanceof Boolean b) return b.toString();

        // For nested object/array, render as compact JSON string so it still fits in a pill.
        try {
            return objectMapper.writeValueAsString(v);
        } catch (Exception ignore) {
            return String.valueOf(v);
        }
    }
}