package dev.notegridx.security.assetvulnmanager.service.importing;

import java.util.List;

public record ImportResult(
        boolean dryRun,
        int linesRead,
        int ok,
        int inserted,
        int updated,
        int skipped,
        int errors,
        List<ImportError> errorList
) {
    public boolean hasErrors() {
        return errors > 0;
    }
}
