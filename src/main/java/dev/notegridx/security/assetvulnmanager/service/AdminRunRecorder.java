package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

@Service
public class AdminRunRecorder {

    @FunctionalInterface
    public interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    private final AdminRunWriteService adminRunWriteService;

    private final ConcurrentMap<AdminJobType, AtomicBoolean> runningMap = new ConcurrentHashMap<>();

    public AdminRunRecorder(AdminRunWriteService adminRunWriteService) {
        this.adminRunWriteService = adminRunWriteService;
    }

    public AdminRun start(AdminJobType jobType, Map<String, Object> params) {
        return adminRunWriteService.start(jobType, params);
    }

    public void success(AdminRun run, Map<String, Object> result) {
        adminRunWriteService.success(run, result);
    }

    public void failed(AdminRun run, Exception ex) {
        adminRunWriteService.failed(run, ex);
    }

    public <T> T runExclusive(
            AdminJobType jobType,
            Map<String, Object> params,
            String alreadyRunningMessage,
            ThrowingSupplier<T> body,
            Function<T, Map<String, Object>> resultMapper
    ) throws Exception {

        AtomicBoolean running = runningMap.computeIfAbsent(jobType, jt -> new AtomicBoolean(false));

        if (!running.compareAndSet(false, true)) {
            throw new AdminJobAlreadyRunningException(alreadyRunningMessage);
        }

        try {
            AdminRun run = start(jobType, params);

            try {
                T result = body.get();
                Map<String, Object> resultMap = (resultMapper == null) ? null : resultMapper.apply(result);
                success(run, resultMap);
                return result;
            } catch (Exception ex) {
                failed(run, ex);
                throw ex;
            }

        } finally {
            running.set(false);
        }
    }

    public boolean isRunning(AdminJobType jobType) {
        AtomicBoolean running = runningMap.get(jobType);
        return running != null && running.get();
    }
}