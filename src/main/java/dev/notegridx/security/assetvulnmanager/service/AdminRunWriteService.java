package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

@Service
public class AdminRunWriteService {

    private final AdminRunRepository repository;
    private final ObjectMapper objectMapper;

    public AdminRunWriteService(AdminRunRepository repository, ObjectMapper objectMapper) {
        this.repository = repository;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public AdminRun start(AdminJobType jobType, Map<String, Object> params) {
        String json = toJson(params);
        AdminRun run = AdminRun.start(jobType, json);
        return repository.save(run);
    }

    @Transactional
    public void success(AdminRun run, Map<String, Object> result) {
        run.markSuccess(toJson(result));
        repository.save(run);
    }

    @Transactional
    public void failed(AdminRun run, Exception ex) {
        String msg = ex.getMessage();
        if (msg != null && msg.length() > 2000) {
            msg = msg.substring(0, 2000);
        }
        run.markFailed(msg);
        repository.save(run);
    }

    private String toJson(Object o) {
        if (o == null) return null;
        try {
            return objectMapper.writeValueAsString(o);
        } catch (JsonProcessingException e) {
            return "{\"error\":\"json-serialize-failed\"}";
        }
    }
}