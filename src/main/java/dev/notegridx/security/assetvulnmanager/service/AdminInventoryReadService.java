package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.ImportRunRepository;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Service
public class AdminInventoryReadService {

    private final ImportRunRepository importRunRepository;
    private final UnresolvedMappingRepository unresolvedMappingRepository;

    public AdminInventoryReadService(
            ImportRunRepository importRunRepository,
            UnresolvedMappingRepository unresolvedMappingRepository
    ) {
        this.importRunRepository = importRunRepository;
        this.unresolvedMappingRepository = unresolvedMappingRepository;
    }

    @Transactional(readOnly = true)
    public List<ImportRun> findImportRuns() {
        List<ImportRun> runs = new ArrayList<>(importRunRepository.findAll());
        runs.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });
        return runs;
    }

    @Transactional(readOnly = true)
    public UnresolvedListView findUnresolvedMappings(
            String status,
            Long runId,
            Boolean activeOnly,
            String activeOnlyPresent,
            Long id
    ) {
        boolean active = effectiveActiveOnly(activeOnly, activeOnlyPresent);

        // ID review mode:
        // if id is specified, show only that mapping and bypass list filters.
        if (id != null) {
            List<UnresolvedMapping> list = unresolvedMappingRepository.findById(id)
                    .map(List::of)
                    .orElseGet(List::of);

            String effectiveStatus = (status == null || status.isBlank())
                    ? "ALL"
                    : status.trim().toUpperCase(Locale.ROOT);

            return new UnresolvedListView(
                    list,
                    effectiveStatus,
                    runId,
                    active,
                    activeOnlyPresent,
                    id
            );
        }

        List<UnresolvedMapping> list = new ArrayList<>(
                active
                        ? unresolvedMappingRepository.findAllActive()
                        : unresolvedMappingRepository.findAll()
        );

        // Status filter:
        // null/blank => NEW
        // ALL => no filtering
        String effectiveStatus = (status == null || status.isBlank())
                ? "NEW"
                : status.trim().toUpperCase(Locale.ROOT);

        if (!"ALL".equals(effectiveStatus)) {
            list.removeIf(m -> m.getStatus() == null || !m.getStatus().equalsIgnoreCase(effectiveStatus));
        }

        // NOTE:
        // runId filtering is not implemented in the current code base.
        // runId is preserved only as UI state.
        list.sort((a, b) -> {
            if (a.getId() == null && b.getId() == null) return 0;
            if (a.getId() == null) return 1;
            if (b.getId() == null) return -1;
            return Long.compare(b.getId(), a.getId());
        });

        return new UnresolvedListView(
                list,
                effectiveStatus,
                runId,
                active,
                activeOnlyPresent,
                null
        );
    }

    /**
     * Checkbox behavior:
     *
     * - When checked, activeOnly=true is sent.
     * - When unchecked, activeOnly is not sent at all.
     *
     * To distinguish this, the form always sends activeOnlyPresent=1.
     * If activeOnlyPresent exists but activeOnly is missing,
     * it means the checkbox was unchecked.
     */
    private static boolean effectiveActiveOnly(Boolean activeOnly, String activeOnlyPresent) {
        // Initial access (no activeOnlyPresent): default true
        if (activeOnlyPresent == null) {
            return (activeOnly == null) ? true : activeOnly;
        }

        // After filter submit: missing activeOnly means unchecked
        return Boolean.TRUE.equals(activeOnly);
    }

    public record UnresolvedListView(
            List<UnresolvedMapping> mappings,
            String status,
            Long runId,
            boolean activeOnly,
            String activeOnlyPresent,
            Long id
    ) {
    }
}