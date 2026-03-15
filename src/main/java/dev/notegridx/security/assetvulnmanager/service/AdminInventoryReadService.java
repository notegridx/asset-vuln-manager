package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class AdminInventoryReadService {

    private final ImportRunRepository importRunRepository;

    public AdminInventoryReadService(ImportRunRepository importRunRepository) {
        this.importRunRepository = importRunRepository;
    }

    @Transactional(readOnly = true)
    public List<ImportRun> findImportRuns() {
        List<ImportRun> runs = importRunRepository.findAll();
        runs.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });
        return runs;
    }
}