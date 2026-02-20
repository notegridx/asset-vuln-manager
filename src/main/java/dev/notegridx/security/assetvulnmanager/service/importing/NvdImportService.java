package dev.notegridx.security.assetvulnmanager.service.importing;

public interface NvdImportService {

    ImportResult importModifiedSince(int daysBack, int maxResults);

    @lombok.Getter
    @lombok.Builder
    class ImportResult {
        private long vulnerabilitiesUpserted;
        private long affectedCpesUpserted;
    }
}
